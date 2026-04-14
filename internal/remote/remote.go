package remote

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/diegovrocha/certui/internal/history"
	"github.com/diegovrocha/certui/internal/inspect"
	"github.com/diegovrocha/certui/internal/ui"
)

type step int

const (
	stepHost step = iota
	stepFetching
	stepResult
)

type Model struct {
	step       step
	hostIn     textinput.Model
	saveIn     textinput.Model
	host       string
	port       string
	tlsVersion string
	cipher     string
	certCount  int
	chainPath  string
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

// New returns a Bubble Tea model for downloading remote certificates.
func New() tea.Model {
	ti := textinput.New()
	ti.Placeholder = "example.com:443"
	ti.Focus()
	return &Model{step: stepHost, hostIn: ti}
}

func (m *Model) Init() tea.Cmd {
	return textinput.Blink
}

type fetchResult struct {
	host       string
	port       string
	tlsVersion string
	cipher     string
	chainPath  string
	certCount  int
	err        string
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
			m.step = stepResult
			return m, nil
		}
		m.host = msg.host
		m.port = msg.port
		m.tlsVersion = msg.tlsVersion
		m.cipher = msg.cipher
		m.chainPath = msg.chainPath
		m.certCount = msg.certCount
		m.step = stepResult
		m.inspectSub = inspect.NewWithFileEmbedded(msg.chainPath)
		var cmd tea.Cmd
		if m.inspectSub != nil {
			cmd = m.inspectSub.Init()
		}
		if !m.logged {
			history.Log("remote_download",
				history.KV("host", fmt.Sprintf("%s:%s", m.host, m.port)),
				history.KV("certs", fmt.Sprintf("%d", m.certCount)))
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
		case stepHost:
			switch msg.String() {
			case "enter":
				raw := strings.TrimSpace(m.hostIn.Value())
				if raw == "" {
					return m, nil
				}
				host, port := parseHostPort(raw)
				m.host = host
				m.port = port
				m.step = stepFetching
				return m, m.doFetch()
			}
			var cmd tea.Cmd
			m.hostIn, cmd = m.hostIn.Update(msg)
			return m, cmd

		case stepResult:
			if m.saving {
				switch msg.String() {
				case "esc":
					m.saving = false
					return m, nil
				case "enter":
					name := strings.TrimSpace(m.saveIn.Value())
					if name == "" {
						name = defaultSaveName(m.host)
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
				m.saveIn.Placeholder = defaultSaveName(m.host)
				m.saveIn.SetValue(defaultSaveName(m.host))
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

func parseHostPort(raw string) (string, string) {
	if i := strings.LastIndex(raw, ":"); i >= 0 {
		return raw[:i], raw[i+1:]
	}
	return raw, "443"
}

func (m *Model) doFetch() tea.Cmd {
	host := m.host
	port := m.port
	return func() tea.Msg {
		addr := fmt.Sprintf("%s:%s", host, port)
		// Note: openssl s_client often exits with code 1 even on success
		// (server closes connection unexpectedly). We ignore the exit code
		// and check if we got certificates in the output. Merge stderr so
		// diagnostic info is available if we fail to parse.
		cmd := exec.Command("bash", "-c",
			fmt.Sprintf("openssl s_client -connect %s -servername %s -showcerts < /dev/null 2>&1",
				shellQuote(addr), shellQuote(host)))
		out, _ := cmd.CombinedOutput()
		raw := string(out)

		tlsVer, cipher := parseProtocol(raw)
		certs := extractCertBlocks(raw)
		if len(certs) == 0 {
			// Try to surface a useful error line from openssl output
			hint := firstErrorLine(raw)
			msg := "Could not reach " + addr
			if hint != "" {
				msg += " — " + hint
			} else {
				msg += " (no certificates returned)"
			}
			return fetchResult{err: msg}
		}

		tmpDir := os.TempDir()
		chainPath := fmt.Sprintf("%s/certui_remote_%s_%d.pem",
			tmpDir, sanitizeName(host), time.Now().UnixNano())
		if err := os.WriteFile(chainPath, []byte(strings.Join(certs, "\n")+"\n"), 0600); err != nil {
			return fetchResult{err: "Could not save chain: " + err.Error()}
		}

		return fetchResult{
			host:       host,
			port:       port,
			tlsVersion: tlsVer,
			cipher:     cipher,
			chainPath:  chainPath,
			certCount:  len(certs),
		}
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func parseProtocol(out string) (string, string) {
	var tlsVer, cipher string
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		// Lines like: "Protocol  : TLSv1.3" or "Protocol: TLSv1.2"
		if strings.HasPrefix(l, "Protocol") && strings.Contains(l, ":") {
			if idx := strings.Index(l, ":"); idx >= 0 {
				tlsVer = strings.TrimSpace(l[idx+1:])
			}
		}
		// "Cipher    : TLS_AES_256_GCM_SHA384"
		if strings.HasPrefix(l, "Cipher") && strings.Contains(l, ":") {
			if idx := strings.Index(l, ":"); idx >= 0 {
				cipher = strings.TrimSpace(l[idx+1:])
			}
		}
	}
	return tlsVer, cipher
}

// firstErrorLine extracts a useful diagnostic from openssl s_client stderr.
func firstErrorLine(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		// Common diagnostic prefixes/patterns
		if strings.Contains(l, "errno=") ||
			strings.Contains(l, "connect:") ||
			strings.Contains(l, "gethostbyname failure") ||
			strings.Contains(l, "getaddrinfo:") ||
			strings.Contains(l, "no route") ||
			strings.Contains(l, "Connection refused") ||
			strings.Contains(l, "timeout") ||
			strings.HasPrefix(l, "verify error:") ||
			strings.HasPrefix(l, "unable to") ||
			strings.Contains(l, "SSL routines") {
			// Trim overly long openssl internal messages
			if len(l) > 120 {
				l = l[:117] + "..."
			}
			return l
		}
	}
	return ""
}

func extractCertBlocks(raw string) []string {
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
		out = append(out, rest[start:end])
		rest = rest[end:]
	}
	return out
}

func sanitizeName(s string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_", "*", "_")
	return r.Replace(s)
}

func defaultSaveName(host string) string {
	h := sanitizeName(host)
	if h == "" {
		h = "remote"
	}
	return h + "_chain.pem"
}

func (m *Model) doSave(name string) tea.Cmd {
	chain := m.chainPath
	return func() tea.Msg {
		data, err := os.ReadFile(chain)
		if err != nil {
			return saveResultMsg{ok: false, message: "Could not read chain: " + err.Error()}
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
	b.WriteString("\n  " + ui.TitleStyle.Render("── Download Certificate from URL ──") + "\n\n")

	switch m.step {
	case stepHost:
		b.WriteString("  " + ui.ActiveStyle.Render("Host and port") + "\n")
		b.WriteString("  " + ui.DimStyle.Render("format: host[:port]  (default port 443)") + "\n\n")
		b.WriteString("  " + m.hostIn.View() + "\n")
		b.WriteString("\n  " + ui.DimStyle.Render("enter fetch  esc back  ctrl+c quit") + "\n")

	case stepFetching:
		b.WriteString("  " + ui.ActiveStyle.Render(fmt.Sprintf("Connecting to %s:%s …", m.host, m.port)) + "\n")

	case stepResult:
		if m.err != "" {
			b.WriteString(ui.ResultBox(false, "Error", m.err))
			b.WriteString("\n  " + ui.DimStyle.Render("esc back  ctrl+c quit") + "\n")
			return b.String()
		}
		// Protocol info above cert details
		b.WriteString(fmt.Sprintf("  %s %s\n", ui.DimStyle.Render("Host:"), ui.ActiveStyle.Render(fmt.Sprintf("%s:%s", m.host, m.port))))
		if m.tlsVersion != "" {
			b.WriteString(fmt.Sprintf("  %s %s\n", ui.DimStyle.Render("TLS:"), m.tlsVersion))
		}
		if m.cipher != "" {
			b.WriteString(fmt.Sprintf("  %s %s\n", ui.DimStyle.Render("Cipher:"), m.cipher))
		}
		b.WriteString(fmt.Sprintf("  %s %d\n", ui.DimStyle.Render("Certs:"), m.certCount))
		b.WriteString("\n")

		if m.saving {
			b.WriteString("  Save chain to file:\n\n")
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
		b.WriteString("\n  " + ui.DimStyle.Render("? help  s save chain  esc back  ctrl+c quit") + "\n")
	}
	return b.String()
}

func (m *Model) renderHelp() string {
	sections := []ui.HelpSection{
		{
			Title: "Input",
			Entries: []ui.HelpEntry{
				{"type", "Enter host[:port]"},
				{"enter", "Fetch chain"},
			},
		},
		{
			Title: "Result",
			Entries: []ui.HelpEntry{
				{"s", "Save chain to file"},
				{"f", "Toggle full view (inspect)"},
				{"y", "Copy to clipboard (inspect)"},
				{"↑/↓", "Scroll (inspect)"},
			},
		},
		ui.CommonHelp(),
	}
	return "\n" + ui.Banner() + "  " + ui.TitleStyle.Render("── Download Certificate from URL ──") + "\n" + ui.RenderHelp("Remote Download — Help", sections)
}
