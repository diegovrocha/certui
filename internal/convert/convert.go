package convert

import (
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/diegovrocha/certui/internal/history"
	"github.com/diegovrocha/certui/internal/ossl"
	"github.com/diegovrocha/certui/internal/ui"
)

type step int

const (
	stepFile step = iota
	stepPassword
	stepBagAttrs
	stepOutput
	stepPassword2
	stepRunning
	stepDone
)

type convType int

const (
	typePfxPem convType = iota
	typePfxCerPem
	typePfxCerDer
	typePfxKey
	typePfxRepack
	typePfxRepackJava
)

type Model struct {
	convType  convType
	step      step
	picker    ui.FilePicker
	input     textinput.Model
	infile    string
	password  string
	password2 string
	keepBag   bool // keep openssl's "Bag Attributes" header lines in the PEM output
	outfile   string
	result    string
	success   bool
	title     string
	showHelp  bool
}

func newModel(ct convType, title string) Model {
	return Model{
		convType: ct,
		step:     stepFile,
		picker:   ui.NewPfxFilePicker("Select the .pfx/.p12 file"),
		title:    title,
	}
}

func NewPfxToPem() tea.Model    { return newModel(typePfxPem, "PFX/P12 → PEM (certificate + key)") }
func NewPfxToCerPem() tea.Model { return newModel(typePfxCerPem, "PFX/P12 → CER (PEM/text)") }
func NewPfxToCerDer() tea.Model { return newModel(typePfxCerDer, "PFX/P12 → CER (DER/binary)") }
func NewPfxToKey() tea.Model    { return newModel(typePfxKey, "PFX/P12 → Private Key") }
func NewPfxRepack() tea.Model {
	return newModel(typePfxRepack, "PFX/P12 → P12 (--legacy → modern)")
}
func NewPfxRepackJava() tea.Model {
	return newModel(typePfxRepackJava, "PFX/P12 → P12 (modern → Java8/legacy)")
}

func (m Model) Init() tea.Cmd { return textinput.Blink }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case convResult:
		m.success = msg.success
		m.result = msg.message
		m.step = stepDone
		if msg.success {
			history.Log("convert",
				history.KV("op", convTypeName(m.convType)),
				history.KV("input", m.infile),
				history.KV("output", m.outfile))
		}
		return m, nil
	case tea.KeyMsg:
		// Help overlay: only on non-input steps (done / running)
		if m.step == stepDone || m.step == stepRunning {
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
		if msg.String() == "esc" {
			return m, nil
		}
	}

	switch m.step {
	case stepFile:
		var cmd tea.Cmd
		m.picker, cmd = m.picker.Update(msg)
		if m.picker.Done {
			m.infile = m.picker.Selected
			m.step = stepPassword
			m.input = textinput.New()
			m.input.Placeholder = "PFX/P12 password"
			m.input.EchoMode = textinput.EchoPassword
			m.input.Focus()
			return m, m.input.Focus()
		}
		return m, cmd

	case stepPassword:
		if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" {
			m.password = m.input.Value()
			if writesPEM(m.convType) {
				m.step = stepBagAttrs
				return m, nil
			}
			return m.toOutput()
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd

	case stepBagAttrs:
		if k, ok := msg.(tea.KeyMsg); ok {
			switch k.String() {
			case "up", "k", "down", "j", "tab":
				m.keepBag = !m.keepBag
			case "enter":
				return m.toOutput()
			}
		}
		return m, nil

	case stepOutput:
		if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" {
			m.outfile = m.input.Value()
			if m.convType == typePfxRepack || m.convType == typePfxRepackJava {
				m.step = stepPassword2
				m.input = textinput.New()
				m.input.Placeholder = "Password for new P12"
				m.input.EchoMode = textinput.EchoPassword
				m.input.Focus()
				return m, m.input.Focus()
			}
			m.step = stepRunning
			return m, m.runConversion()
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd

	case stepPassword2:
		if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" {
			m.password2 = m.input.Value()
			m.step = stepRunning
			return m, m.runConversion()
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}

	return m, nil
}

// toOutput moves to the output-file step with a default name for the type.
func (m Model) toOutput() (tea.Model, tea.Cmd) {
	base := strings.TrimSuffix(filepath.Base(m.infile), filepath.Ext(m.infile))
	name := base + ".pem"
	switch m.convType {
	case typePfxRepack, typePfxRepackJava:
		name = base + "_new.p12"
	case typePfxCerPem, typePfxCerDer:
		name = base + ".cer"
	case typePfxKey:
		name = base + ".key"
	}
	m.step = stepOutput
	m.input = textinput.New()
	m.input.SetValue(name)
	return m, m.input.Focus()
}

// writesPEM reports whether the type writes openssl pkcs12 PEM output, which
// carries "Bag Attributes" lines unless they are stripped.
func writesPEM(ct convType) bool {
	return ct == typePfxPem || ct == typePfxCerPem || ct == typePfxKey
}

type convResult struct {
	success bool
	message string
}

func (m Model) runConversion() tea.Cmd {
	return func() tea.Msg {
		msg, err := runConvert(m.convType, m.infile, m.password, m.password2, m.outfile, m.keepBag)
		if err != nil {
			return convResult{false, err.Error()}
		}
		return convResult{true, msg}
	}
}

// runConvert performs the conversion and returns the success line for the
// result box. Passwords reach openssl through the environment (ossl.PassIn /
// ossl.PassOut), and intermediate PEMs holding private keys are unique 0600
// temp files removed before returning.
func runConvert(ct convType, infile, password, password2, outfile string, keepBag bool) (string, error) {
	if sameFile(infile, outfile) {
		return "", errors.New("output file must be different from the input file")
	}
	legacy := detectLegacy()
	pkcs12In := func(out string, flags ...string) error {
		args := append([]string{"pkcs12", "-in", infile, "-out", out, "-passin", ossl.PassIn}, flags...)
		return ossl.Run(password, "", append(args, legacy...)...)
	}
	// pkcs12Out writes the final PEM file, honouring keepBag.
	pkcs12Out := func(flags ...string) error {
		if err := pkcs12In(outfile, flags...); err != nil {
			return err
		}
		if keepBag {
			return nil
		}
		return stripBagAttributes(outfile)
	}

	switch ct {
	case typePfxPem:
		if err := pkcs12Out("-nodes"); err != nil {
			return "", fmt.Errorf("Extraction failed: %w", err)
		}
		if err := os.Chmod(outfile, 0o600); err != nil {
			return "", err
		}
		return "File: " + outfile + "  Permission: 600", nil

	case typePfxCerPem:
		if err := pkcs12Out("-nokeys", "-clcerts"); err != nil {
			return "", fmt.Errorf("Extraction failed: %w", err)
		}
		return "Format: PEM (text)", nil

	case typePfxCerDer:
		tmp, cleanup, err := ossl.TempFile("certui_conv_*.pem")
		if err != nil {
			return "", err
		}
		defer cleanup()
		if err := pkcs12In(tmp, "-nokeys", "-clcerts"); err != nil {
			return "", fmt.Errorf("Extraction failed: %w", err)
		}
		if err := ossl.Run("", "", "x509", "-in", tmp, "-out", outfile, "-outform", "DER"); err != nil {
			return "", fmt.Errorf("DER conversion failed: %w", err)
		}
		return "Format: DER (binary)", nil

	case typePfxKey:
		if err := pkcs12Out("-nocerts", "-nodes"); err != nil {
			return "", fmt.Errorf("Extraction failed: %w", err)
		}
		// openssl keeps the mode of an existing file, so enforce it.
		if err := os.Chmod(outfile, 0o600); err != nil {
			return "", err
		}
		return "Permission: 600", nil

	case typePfxRepack, typePfxRepackJava:
		tmp, cleanup, err := ossl.TempFile("certui_repack_*.pem")
		if err != nil {
			return "", err
		}
		defer cleanup()
		if err := pkcs12In(tmp, "-nodes"); err != nil {
			return "", fmt.Errorf("Extraction failed: %w", err)
		}
		args := []string{"pkcs12", "-export", "-in", tmp, "-out", outfile, "-passout", ossl.PassOut}
		if ct == typePfxRepackJava {
			args = append(args, "-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1")
			if err := ossl.Run("", password2, args...); err != nil {
				return "", fmt.Errorf("Repack (Java8) failed: %w", err)
			}
			return "Converted modern → Java8/legacy (3DES+SHA1)", nil
		}
		if err := ossl.Run("", password2, args...); err != nil {
			return "", fmt.Errorf("Repack failed: %w", err)
		}
		return "Converted --legacy → modern (AES-256-CBC)", nil
	}

	return "", errors.New("Unknown type")
}

// stripBagAttributes rewrites a PEM file keeping only its PEM blocks, which
// drops the "Bag Attributes" / "subject=" / "issuer=" lines openssl pkcs12
// prints before each block. Some portals reject files that carry them.
func stripBagAttributes(file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var out []byte
	for rest := data; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		out = append(out, pem.EncodeToMemory(b)...)
	}
	if len(out) == 0 {
		return nil
	}
	// WriteFile keeps the mode of the existing file (600 for keys).
	return os.WriteFile(file, out, 0o600)
}

// sameFile reports whether a and b refer to the same existing file.
func sameFile(a, b string) bool {
	sa, err1 := os.Stat(a)
	sb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(sa, sb)
}

func (m Model) View() string {
	if m.showHelp {
		return m.renderHelp()
	}
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(ui.Banner())
	b.WriteString("\n  " + ui.TitleStyle.Render("── "+m.title+" ──") + "\n\n")

	switch m.step {
	case stepFile:
		b.WriteString(m.picker.View())

	case stepPassword, stepPassword2:
		b.WriteString(fmt.Sprintf("  File: %s\n\n", ui.ActiveStyle.Render(m.infile)))
		label := "PFX/P12 password"
		if m.step == stepPassword2 {
			label = "Password for new P12"
		}
		b.WriteString(fmt.Sprintf("  🔑 %s\n\n", label))
		b.WriteString("  " + m.input.View() + "\n")

	case stepBagAttrs:
		b.WriteString(fmt.Sprintf("  File: %s\n\n", ui.ActiveStyle.Render(m.infile)))
		b.WriteString("  Bag Attributes (localKeyID, friendlyName, subject/issuer lines before each block):\n\n")
		opts := []string{
			"Remove — clean PEM, only the BEGIN/END blocks (recommended for banks and portals)",
			"Keep — openssl's default output",
		}
		sel := 0
		if m.keepBag {
			sel = 1
		}
		for i, o := range opts {
			if i == sel {
				b.WriteString("  " + ui.ActiveStyle.Render("▸ "+o) + "\n")
			} else {
				b.WriteString("    " + ui.DimStyle.Render(o) + "\n")
			}
		}

	case stepOutput:
		b.WriteString("  Output file:\n\n")
		b.WriteString("  " + m.input.View() + "\n")

	case stepRunning:
		b.WriteString("  ⏳ Processing...\n")

	case stepDone:
		if m.success {
			b.WriteString(ui.ResultBox(true, "Success!", m.result))
		} else {
			b.WriteString(ui.ResultBox(false, "Error", m.result))
		}
	}

	b.WriteString("\n  " + ui.DimStyle.Render("? help  esc back  enter confirm  ctrl+c quit") + "\n")
	return b.String()
}

func (m Model) renderHelp() string {
	sections := []ui.HelpSection{
		{
			Title: "Steps",
			Entries: []ui.HelpEntry{
				{Key: "enter", Desc: "Confirm current step"},
				{Key: "type", Desc: "Fill file / password / output fields"},
			},
		},
		{
			Title: "File picker",
			Entries: []ui.HelpEntry{
				{Key: "↑/↓", Desc: "Navigate entries"},
				{Key: "→ / enter", Desc: "Open folder"},
				{Key: "←", Desc: "Parent folder"},
				{Key: "type", Desc: "Filter entries"},
			},
		},
		ui.CommonHelp(),
	}
	return "\n" + ui.Banner() + "  " + ui.TitleStyle.Render("── "+m.title+" ──") + "\n" + ui.RenderHelp("Convert — Help", sections)
}

func detectLegacy() []string { return ossl.DetectLegacy() }

func runOpenSSL(args ...string) error { return ossl.Run("", "", args...) }

func convTypeName(ct convType) string {
	switch ct {
	case typePfxPem:
		return "pfx_to_pem"
	case typePfxCerPem:
		return "pfx_to_cer_pem"
	case typePfxCerDer:
		return "pfx_to_cer_der"
	case typePfxKey:
		return "pfx_to_key"
	case typePfxRepack:
		return "pfx_repack"
	case typePfxRepackJava:
		return "pfx_repack_java"
	}
	return "unknown"
}

// CapturesEsc tells the menu to forward esc to this screen instead of
// returning to the main menu (help overlay or a nested view is open).
func (m Model) CapturesEsc() bool { return m.showHelp }
