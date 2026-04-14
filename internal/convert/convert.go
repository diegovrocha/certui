package convert

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/diegovrocha/certui/internal/history"
	"github.com/diegovrocha/certui/internal/ui"
)

type step int

const (
	stepFile step = iota
	stepPassword
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
)

type Model struct {
	convType  convType
	step      step
	picker    ui.FilePicker
	input     textinput.Model
	infile    string
	password  string
	password2 string
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
			base := strings.TrimSuffix(filepath.Base(m.infile), filepath.Ext(m.infile))

			if m.convType == typePfxRepack {
				m.step = stepOutput
				m.input = textinput.New()
				m.input.SetValue(base + "_new.p12")
				m.input.Focus()
				return m, m.input.Focus()
			}

			ext := ".pem"
			switch m.convType {
			case typePfxCerPem, typePfxCerDer:
				ext = ".cer"
			case typePfxKey:
				ext = ".key"
			}
			m.step = stepOutput
			m.input = textinput.New()
			m.input.SetValue(base + ext)
			m.input.Focus()
			return m, m.input.Focus()
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd

	case stepOutput:
		if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" {
			m.outfile = m.input.Value()
			if m.convType == typePfxRepack {
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

type convResult struct {
	success bool
	message string
}

func (m Model) runConversion() tea.Cmd {
	return func() tea.Msg {
		legacy := detectLegacy()

		switch m.convType {
		case typePfxPem:
			args := append([]string{"pkcs12", "-in", m.infile, "-out", m.outfile,
				"-passin", "pass:" + m.password, "-nodes"}, legacy...)
			if err := runOpenSSL(args...); err != nil {
				return convResult{false, "Extraction failed: " + err.Error()}
			}
			return convResult{true, "File: " + m.outfile}

		case typePfxCerPem:
			args := append([]string{"pkcs12", "-in", m.infile, "-out", m.outfile,
				"-passin", "pass:" + m.password, "-nokeys", "-clcerts"}, legacy...)
			if err := runOpenSSL(args...); err != nil {
				return convResult{false, "Extraction failed: " + err.Error()}
			}
			return convResult{true, "Format: PEM (text)"}

		case typePfxCerDer:
			tmp := "/tmp/certui_tmp.pem"
			args := append([]string{"pkcs12", "-in", m.infile, "-out", tmp,
				"-passin", "pass:" + m.password, "-nokeys", "-clcerts"}, legacy...)
			if err := runOpenSSL(args...); err != nil {
				return convResult{false, "Extraction failed: " + err.Error()}
			}
			if err := runOpenSSL("x509", "-in", tmp, "-out", m.outfile, "-outform", "DER"); err != nil {
				return convResult{false, "DER conversion failed: " + err.Error()}
			}
			return convResult{true, "Format: DER (binary)"}

		case typePfxKey:
			args := append([]string{"pkcs12", "-in", m.infile, "-out", m.outfile,
				"-passin", "pass:" + m.password, "-nocerts", "-nodes"}, legacy...)
			if err := runOpenSSL(args...); err != nil {
				return convResult{false, "Extraction failed: " + err.Error()}
			}
			return convResult{true, "Permission: 600"}

		case typePfxRepack:
			tmp := "/tmp/certui_repack.pem"
			args := append([]string{"pkcs12", "-in", m.infile, "-out", tmp,
				"-passin", "pass:" + m.password, "-nodes"}, legacy...)
			if err := runOpenSSL(args...); err != nil {
				return convResult{false, "Extraction failed (--legacy): " + err.Error()}
			}
			if err := runOpenSSL("pkcs12", "-export", "-in", tmp, "-out", m.outfile,
				"-passout", "pass:"+m.password2); err != nil {
				return convResult{false, "Repack failed: " + err.Error()}
			}
			return convResult{true, "Converted --legacy → modern (AES-256-CBC)"}
		}

		return convResult{false, "Unknown type"}
	}
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
				{"enter", "Confirm current step"},
				{"type", "Fill file / password / output fields"},
			},
		},
		{
			Title: "File picker",
			Entries: []ui.HelpEntry{
				{"↑/↓", "Navigate entries"},
				{"→ / enter", "Open folder"},
				{"←", "Parent folder"},
				{"type", "Filter entries"},
			},
		},
		ui.CommonHelp(),
	}
	return "\n" + ui.Banner() + "  " + ui.TitleStyle.Render("── "+m.title+" ──") + "\n" + ui.RenderHelp("Convert — Help", sections)
}

func detectLegacy() []string {
	out, _ := exec.Command("openssl", "list", "-providers").Output()
	if strings.Contains(strings.ToLower(string(out)), "legacy") {
		return []string{"-legacy"}
	}
	out2, _ := exec.Command("openssl", "pkcs12", "-help").CombinedOutput()
	if strings.Contains(string(out2), "-legacy") {
		return []string{"-legacy"}
	}
	return nil
}

func runOpenSSL(args ...string) error {
	return exec.Command("openssl", args...).Run()
}

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
	}
	return "unknown"
}
