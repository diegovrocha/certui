// Package fetchca downloads the issuer CA chain of a certificate by following
// the Authority Information Access (AIA) "CA Issuers" URL hop by hop, from the
// selected leaf certificate up to the root (subject == issuer) or until a
// certificate without an AIA URL is reached.
package fetchca

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/diegovrocha/certui/internal/history"
	"github.com/diegovrocha/certui/internal/inspect"
	"github.com/diegovrocha/certui/internal/ui"
)

type step int

const (
	stepFile step = iota
	stepFetching
	stepResult
)

// maxHops bounds the AIA walk to avoid runaway loops on misconfigured chains.
const maxHops = 10

type Model struct {
	step       step
	picker     ui.FilePicker
	saveIn     textinput.Model
	infile     string
	leafCN     string
	hops       []string // human-readable log of each AIA hop
	chainPath  string   // temp PEM holding the downloaded CA chain
	certCount  int
	inspectSub tea.Model
	err        string
	saving     bool
	saveResult string
	saveOk     bool
	saveMsgExp time.Time
	logged     bool
	height     int
	width      int
	showHelp   bool
}

// New returns a Bubble Tea model that fetches a certificate's issuer CA chain.
func New() tea.Model {
	return &Model{
		step:   stepFile,
		picker: ui.NewCertOnlyPicker("Select the certificate to read its AIA"),
	}
}

func (m *Model) Init() tea.Cmd {
	return textinput.Blink
}

type fetchResult struct {
	leafCN    string
	hops      []string
	chainPath string
	certCount int
	err       string
}

type saveResultMsg struct {
	ok      bool
	message string
}

type clearSaveMsg struct{}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.height = msg.Height
		m.width = msg.Width
		if m.inspectSub != nil {
			m.inspectSub, _ = m.inspectSub.Update(msg)
		}
		return m, nil

	case fetchResult:
		if msg.err != "" {
			m.err = msg.err
			m.hops = msg.hops
			m.leafCN = msg.leafCN
			m.step = stepResult
			return m, nil
		}
		m.leafCN = msg.leafCN
		m.hops = msg.hops
		m.chainPath = msg.chainPath
		m.certCount = msg.certCount
		m.step = stepResult
		m.inspectSub = inspect.NewWithFileEmbedded(msg.chainPath)
		var cmd tea.Cmd
		if m.inspectSub != nil {
			cmd = m.inspectSub.Init()
		}
		if !m.logged {
			history.Log("fetch_ca",
				history.KV("file", m.infile),
				history.KV("ca_certs", fmt.Sprintf("%d", m.certCount)))
			m.logged = true
		}
		return m, cmd

	case saveResultMsg:
		m.saving = false
		m.saveOk = msg.ok
		m.saveResult = msg.message
		m.saveMsgExp = time.Now().Add(3 * time.Second)
		return m, tea.Tick(3100*time.Millisecond, func(time.Time) tea.Msg { return clearSaveMsg{} })

	case clearSaveMsg:
		if !time.Now().Before(m.saveMsgExp) {
			m.saveResult = ""
		}
		return m, nil

	case tea.KeyMsg:
		// Help overlay: only on stepResult when not saving
		if m.step == stepResult && !m.saving {
			if msg.String() == "?" {
				m.showHelp = !m.showHelp
				return m, nil
			}
			if m.showHelp {
				if msg.String() == "esc" {
					m.showHelp = false
					return m, nil
				}
				return m, nil
			}
		}
		switch m.step {
		case stepFile:
			var cmd tea.Cmd
			m.picker, cmd = m.picker.Update(msg)
			if m.picker.Done {
				m.infile = m.picker.Selected
				m.step = stepFetching
				return m, m.doFetch()
			}
			return m, cmd

		case stepResult:
			if m.err != "" {
				return m, nil
			}
			if m.saving {
				switch msg.String() {
				case "esc":
					m.saving = false
					return m, nil
				case "enter":
					name := strings.TrimSpace(m.saveIn.Value())
					if name == "" {
						name = defaultSaveName(m.leafCN)
					}
					return m, m.doSave(name)
				}
				var cmd tea.Cmd
				m.saveIn, cmd = m.saveIn.Update(msg)
				return m, cmd
			}
			switch msg.String() {
			case "s", "S":
				m.saving = true
				m.saveResult = ""
				m.saveIn = textinput.New()
				m.saveIn.Placeholder = defaultSaveName(m.leafCN)
				m.saveIn.SetValue(defaultSaveName(m.leafCN))
				m.saveIn.Focus()
				return m, m.saveIn.Focus()
			}
			// Delegate other keys to the inspect sub-model so scroll/full-view work.
			if m.inspectSub != nil {
				var cmd tea.Cmd
				m.inspectSub, cmd = m.inspectSub.Update(msg)
				return m, cmd
			}
		}
	}

	// Fallthrough to sub-model for non-key messages.
	if m.step == stepResult && m.inspectSub != nil {
		var cmd tea.Cmd
		m.inspectSub, cmd = m.inspectSub.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *Model) doFetch() tea.Cmd {
	infile := m.infile
	return func() tea.Msg {
		leafPEM, err := normalizeToPEM(infile)
		if err != nil {
			return fetchResult{err: err.Error()}
		}
		leafCN := subjectCN(leafPEM)

		var hops []string
		var chainPEMs []string
		seen := map[string]bool{}
		current := leafPEM

		for hop := 0; hop < maxHops; hop++ {
			if subjectEqualsIssuer(current) {
				// Reached a self-signed certificate — it is the root.
				break
			}
			url := aiaCAIssuersURL(current)
			if url == "" {
				break
			}

			dest := tmpPath(fmt.Sprintf("ca_dl_%d", hop), "")
			if derr := download(url, dest); derr != nil {
				if len(chainPEMs) == 0 {
					return fetchResult{leafCN: leafCN, err: "Could not download CA from " + url + " — " + derr.Error()}
				}
				hops = append(hops, "✖ "+url+" ("+derr.Error()+")")
				break
			}

			certPEMs, perr := extractCertsToPEM(dest)
			if perr != nil || len(certPEMs) == 0 {
				if len(chainPEMs) == 0 {
					return fetchResult{leafCN: leafCN, err: "Downloaded file from " + url + " is not a recognized certificate (PEM/DER/PKCS7)"}
				}
				hops = append(hops, "✖ "+url+" (unrecognized format)")
				break
			}

			hops = append(hops, fmt.Sprintf("↓ %s", url))
			chainPEMs = append(chainPEMs, certPEMs...)

			// A single cert means a normal one-issuer hop: keep walking from it.
			// Multiple certs means the AIA returned a full bundle: stop here.
			if len(certPEMs) != 1 {
				break
			}
			next := tmpPath(fmt.Sprintf("ca_hop_%d", hop), ".pem")
			if werr := os.WriteFile(next, []byte(certPEMs[0]+"\n"), 0600); werr != nil {
				break
			}
			subj := subjectOf(next)
			if subj == "" || seen[subj] {
				break
			}
			seen[subj] = true
			current = next
		}

		if len(chainPEMs) == 0 {
			if subjectEqualsIssuer(leafPEM) {
				return fetchResult{leafCN: leafCN, err: "This certificate is self-signed (it is its own CA) — nothing to fetch."}
			}
			return fetchResult{leafCN: leafCN, err: "No AIA \"CA Issuers\" URL in this certificate. Request the CA bundle from the provider (e.g. Crednosso/TecBan)."}
		}

		chainPath := tmpPath("ca_chain", ".pem")
		if werr := os.WriteFile(chainPath, []byte(strings.Join(chainPEMs, "\n")+"\n"), 0600); werr != nil {
			return fetchResult{leafCN: leafCN, err: "Could not save CA chain: " + werr.Error()}
		}

		return fetchResult{
			leafCN:    leafCN,
			hops:      hops,
			chainPath: chainPath,
			certCount: len(chainPEMs),
		}
	}
}

func (m *Model) doSave(name string) tea.Cmd {
	chain := m.chainPath
	return func() tea.Msg {
		data, err := os.ReadFile(chain)
		if err != nil {
			return saveResultMsg{ok: false, message: "Could not read CA chain: " + err.Error()}
		}
		if err := os.WriteFile(name, data, 0644); err != nil {
			return saveResultMsg{ok: false, message: "Could not save: " + err.Error()}
		}
		return saveResultMsg{ok: true, message: "File: " + name}
	}
}

func (m *Model) View() string {
	if m.showHelp {
		return m.renderHelp()
	}
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(ui.Banner())
	b.WriteString("\n  " + ui.TitleStyle.Render("── Fetch Issuer CA (AIA) ──") + "\n\n")

	switch m.step {
	case stepFile:
		b.WriteString(m.picker.View())

	case stepFetching:
		b.WriteString("  " + ui.ActiveStyle.Render("Reading AIA and downloading CA chain …") + "\n")

	case stepResult:
		if m.err != "" {
			b.WriteString(ui.ResultBox(false, "Could not fetch CA", m.err))
			if len(m.hops) > 0 {
				b.WriteString("\n\n  " + ui.DimStyle.Render("AIA hops:") + "\n")
				for _, h := range m.hops {
					b.WriteString("    " + ui.DimStyle.Render(h) + "\n")
				}
			}
			b.WriteString("\n  " + ui.DimStyle.Render("esc back  ctrl+c quit") + "\n")
			return b.String()
		}

		if m.leafCN != "" {
			b.WriteString(fmt.Sprintf("  %s %s\n", ui.DimStyle.Render("From cert:"), ui.ActiveStyle.Render(m.leafCN)))
		}
		b.WriteString(fmt.Sprintf("  %s %d\n", ui.DimStyle.Render("CA certs:"), m.certCount))
		if len(m.hops) > 0 {
			b.WriteString("\n  " + ui.DimStyle.Render("AIA hops:") + "\n")
			for _, h := range m.hops {
				b.WriteString("    " + ui.DimStyle.Render(h) + "\n")
			}
		}
		b.WriteString("\n")

		if m.saving {
			b.WriteString("  Save CA chain to file:\n\n")
			b.WriteString("  " + m.saveIn.View() + "\n")
			b.WriteString("\n  " + ui.DimStyle.Render("enter save  esc cancel  ctrl+c quit") + "\n")
			return b.String()
		}

		if m.inspectSub != nil {
			b.WriteString(m.inspectSub.View())
		}

		if m.saveResult != "" && time.Now().Before(m.saveMsgExp) {
			b.WriteString("\n")
			if m.saveOk {
				b.WriteString(ui.ResultBox(true, "Saved", m.saveResult))
			} else {
				b.WriteString(ui.ResultBox(false, "Error", m.saveResult))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n  " + ui.DimStyle.Render("? help  s save CA chain  esc back  ctrl+c quit") + "\n")
	}
	return b.String()
}

func (m *Model) renderHelp() string {
	sections := []ui.HelpSection{
		{
			Title: "Input",
			Entries: []ui.HelpEntry{
				{Key: "pick", Desc: "Select a certificate (PEM/CER/CRT)"},
			},
		},
		{
			Title: "Result",
			Entries: []ui.HelpEntry{
				{Key: "s", Desc: "Save CA chain to .pem"},
				{Key: "f", Desc: "Toggle full view (inspect)"},
				{Key: "y", Desc: "Copy to clipboard (inspect)"},
				{Key: "↑/↓", Desc: "Scroll (inspect)"},
			},
		},
		ui.CommonHelp(),
	}
	return "\n" + ui.Banner() + "  " + ui.TitleStyle.Render("── Fetch Issuer CA (AIA) ──") + "\n" + ui.RenderHelp("Fetch Issuer CA — Help", sections)
}

// --- helpers (shell out to openssl/curl) ---

// normalizeToPEM returns a path to a PEM-encoded copy of the certificate at
// path. PEM files are returned as-is; DER files are converted to a temp PEM.
func normalizeToPEM(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("could not read certificate: %s", err.Error())
	}
	if strings.Contains(string(data), "BEGIN CERTIFICATE") {
		return path, nil
	}
	out, derr := exec.Command("openssl", "x509", "-inform", "DER", "-in", path, "-outform", "PEM").Output()
	if derr == nil && strings.Contains(string(out), "BEGIN CERTIFICATE") {
		dest := tmpPath("ca_leaf", ".pem")
		if werr := os.WriteFile(dest, out, 0600); werr != nil {
			return "", fmt.Errorf("could not write temp PEM: %s", werr.Error())
		}
		return dest, nil
	}
	return "", fmt.Errorf("unrecognized certificate format (expected PEM or DER)")
}

// aiaCAIssuersURL returns the AIA "CA Issuers" URI of the PEM certificate, or "".
func aiaCAIssuersURL(pemFile string) string {
	out, _ := exec.Command("openssl", "x509", "-in", pemFile, "-noout", "-text").Output()
	return parseCAIssuersURL(string(out))
}

// parseCAIssuersURL extracts the "CA Issuers - URI:" value from openssl -text output.
func parseCAIssuersURL(text string) string {
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		if strings.Contains(l, "CA Issuers") {
			if i := strings.Index(l, "URI:"); i >= 0 {
				return strings.TrimSpace(l[i+4:])
			}
		}
	}
	return ""
}

func certField(pemFile, flag string) string {
	out, _ := exec.Command("openssl", "x509", "-in", pemFile, "-noout", flag).Output()
	return strings.TrimSpace(string(out))
}

func subjectOf(pemFile string) string {
	return strings.TrimSpace(strings.TrimPrefix(certField(pemFile, "-subject"), "subject="))
}

func subjectEqualsIssuer(pemFile string) bool {
	s := subjectOf(pemFile)
	i := strings.TrimSpace(strings.TrimPrefix(certField(pemFile, "-issuer"), "issuer="))
	return s != "" && s == i
}

func subjectCN(pemFile string) string {
	subj := subjectOf(pemFile)
	for _, part := range strings.Split(subj, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") || strings.HasPrefix(part, "CN =") {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(part, "CN="), "CN ="))
		}
	}
	return subj
}

// download fetches url into dest using curl, failing on HTTP errors.
func download(url, dest string) error {
	out, err := exec.Command("curl", "-fsSL", "--max-time", "20", "-o", dest, url).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		if len(msg) > 120 {
			msg = msg[:117] + "..."
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// extractCertsToPEM reads a downloaded CA file (PEM, DER, or PKCS7/.p7c) and
// returns the contained certificates as PEM text blocks.
func extractCertsToPEM(file string) ([]string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	content := string(data)
	if strings.Contains(content, "BEGIN CERTIFICATE") {
		if blocks := certBlocks(content); len(blocks) > 0 {
			return blocks, nil
		}
	}
	// Single DER X.509 certificate.
	if out, e := exec.Command("openssl", "x509", "-inform", "DER", "-in", file, "-outform", "PEM").Output(); e == nil {
		if blocks := certBlocks(string(out)); len(blocks) > 0 {
			return blocks, nil
		}
	}
	// PKCS7 bundle (DER then PEM) — common for AIA ".p7c" URLs.
	if out, e := exec.Command("openssl", "pkcs7", "-inform", "DER", "-in", file, "-print_certs").Output(); e == nil {
		if blocks := certBlocks(string(out)); len(blocks) > 0 {
			return blocks, nil
		}
	}
	if out, e := exec.Command("openssl", "pkcs7", "-inform", "PEM", "-in", file, "-print_certs").Output(); e == nil {
		if blocks := certBlocks(string(out)); len(blocks) > 0 {
			return blocks, nil
		}
	}
	return nil, fmt.Errorf("unrecognized format")
}

// certBlocks splits PEM text into individual BEGIN/END CERTIFICATE blocks.
func certBlocks(raw string) []string {
	var out []string
	rest := raw
	for {
		start := strings.Index(rest, "-----BEGIN CERTIFICATE-----")
		if start == -1 {
			break
		}
		end := strings.Index(rest[start:], "-----END CERTIFICATE-----")
		if end == -1 {
			break
		}
		end += start + len("-----END CERTIFICATE-----")
		out = append(out, strings.TrimSpace(rest[start:end]))
		rest = rest[end:]
	}
	return out
}

func tmpPath(prefix, ext string) string {
	return fmt.Sprintf("%s/certui_%s_%d%s", os.TempDir(), prefix, time.Now().UnixNano(), ext)
}

func defaultSaveName(leafCN string) string {
	base := sanitize(leafCN)
	if base == "" {
		base = "cert"
	}
	return base + "_ca_chain.pem"
}

func sanitize(s string) string {
	r := strings.NewReplacer(
		"*", "_", " ", "_", "/", "_", "\\", "_",
		":", "_", "?", "_", "\"", "_", "<", "_",
		">", "_", "|", "_",
	)
	return strings.Trim(r.Replace(s), "._")
}

// CapturesEsc tells the menu to forward esc to this screen instead of
// returning to the main menu (help overlay or a nested view is open).
func (m *Model) CapturesEsc() bool { return m.showHelp || m.saving }
