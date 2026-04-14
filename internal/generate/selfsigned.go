package generate

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/diegovrocha/certui/internal/history"
	"github.com/diegovrocha/certui/internal/ui"
)

type genStep int

const (
	genDays genStep = iota
	genAlgo
	genBits
	genCurve
	genOutCert
	genOutKey
	genCN
	genSANPreset
	genSANCustom
	genOrg
	genOU
	genCountry
	genState
	genCity
	genRunning
	genDone
)

// SAN presets
var sanPresetLabels = []string{
	"None                    (just CN)",
	"Web                     (CN + localhost + 127.0.0.1 + ::1)",
	"Wildcard                (CN + *.CN)",
	"Wildcard + Web          (CN + *.CN + localhost + 127.0.0.1 + ::1)",
	"Custom                  (type your own list)",
}

// Algorithm choices
var algoLabels = []string{
	"RSA  (traditional, broad compatibility)",
	"EC   (modern, faster, smaller keys — recommended)",
}

// EC curve choices (openssl name, display label)
var curveOptions = []struct {
	name  string
	label string
}{
	{"prime256v1", "P-256  (256 bits — TLS 1.3 default, recommended)"},
	{"secp384r1", "P-384  (384 bits — NSA Suite B)"},
	{"secp521r1", "P-521  (521 bits — paranoid)"},
}

type Model struct {
	step    genStep
	input   textinput.Model
	optCur  int
	days    string
	algo    string // "RSA" or "EC"
	bits    string // RSA: "2048"/"4096"; EC: empty
	curve   string // EC: "prime256v1" etc.; RSA: empty
	outCert string
	outKey  string
	cn      string
	sans    []string
	sanDesc string // human description for the summary
	org     string
	ou      string
	country string
	state   string
	city    string
	result  string
	success bool
	showHelp bool
}

func NewSelfSigned() tea.Model {
	return &Model{step: genDays, optCur: 2} // default 365
}

func (m *Model) Init() tea.Cmd {
	return nil
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Help overlay: enable on choice steps and the done step
		if isChoiceStep(m.step) || m.step == genDone || m.step == genRunning {
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
		switch msg.String() {
		case "esc":
			return m, nil
		case "up", "k":
			if isChoiceStep(m.step) && m.optCur > 0 {
				m.optCur--
			}
			return m, nil
		case "down", "j":
			if isChoiceStep(m.step) {
				if m.optCur < choiceMax(m.step) {
					m.optCur++
				}
			}
			return m, nil
		case "enter":
			return m.advance()
		}
	case genResult:
		m.success = msg.success
		m.result = msg.message
		m.step = genDone
		if msg.success {
			algoDesc := m.algo
			if m.algo == "RSA" {
				algoDesc = "RSA-" + m.bits
			} else if m.algo == "EC" {
				algoDesc = "EC-" + m.curve
			}
			history.Log("generate_self_signed",
				history.KV("cn", m.cn),
				history.KV("days", m.days),
				history.KV("algo", algoDesc),
				history.KV("sans", fmt.Sprintf("%d", len(m.sans))),
				history.KV("output", m.outCert))
		}
		return m, nil
	}

	if isInputStep(m.step) {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	return m, nil
}

type genResult struct {
	success bool
	message string
}

func isInputStep(s genStep) bool {
	return s == genCN || s == genOrg || s == genOU || s == genCountry ||
		s == genState || s == genCity || s == genOutCert || s == genOutKey ||
		s == genSANCustom
}

func isChoiceStep(s genStep) bool {
	return s == genDays || s == genAlgo || s == genBits || s == genCurve || s == genSANPreset
}

func choiceMax(s genStep) int {
	switch s {
	case genDays:
		return 4 // 5 options (0-4)
	case genAlgo:
		return 1 // 2 options
	case genBits:
		return 1 // 2 options (0-1)
	case genCurve:
		return len(curveOptions) - 1
	case genSANPreset:
		return len(sanPresetLabels) - 1
	}
	return 0
}

func (m *Model) newInput(placeholder string) tea.Cmd {
	m.input = textinput.New()
	m.input.Placeholder = placeholder
	m.input.Focus()
	return m.input.Focus()
}

func (m *Model) newInputWithValue(value string) tea.Cmd {
	m.input = textinput.New()
	m.input.SetValue(value)
	m.input.Focus()
	return m.input.Focus()
}

func (m *Model) advance() (tea.Model, tea.Cmd) {
	switch m.step {
	case genDays:
		days := []string{"30", "90", "365", "730", "3650"}
		m.days = days[m.optCur]
		m.step = genAlgo
		m.optCur = 1 // default EC (recommended)

	case genAlgo:
		if m.optCur == 0 {
			m.algo = "RSA"
			m.step = genBits
			m.optCur = 0
		} else {
			m.algo = "EC"
			m.step = genCurve
			m.optCur = 0 // default P-256
		}

	case genBits:
		bits := []string{"2048", "4096"}
		m.bits = bits[m.optCur]
		m.step = genOutCert
		return m, m.newInput("certificate.crt")

	case genCurve:
		m.curve = curveOptions[m.optCur].name
		m.step = genOutCert
		return m, m.newInput("certificate.crt")

	case genOutCert:
		m.outCert = m.input.Value()
		if m.outCert == "" {
			m.outCert = "certificate.crt"
		}
		m.step = genOutKey
		// Suggest .key based on the cert name
		base := strings.TrimSuffix(m.outCert, ".crt")
		base = strings.TrimSuffix(base, ".pem")
		return m, m.newInput(base + ".key")

	case genOutKey:
		m.outKey = m.input.Value()
		if m.outKey == "" {
			base := strings.TrimSuffix(m.outCert, ".crt")
			base = strings.TrimSuffix(base, ".pem")
			m.outKey = base + ".key"
		}
		m.step = genCN
		return m, m.newInput("mysite.local")

	case genCN:
		m.cn = m.input.Value()
		if m.cn == "" {
			return m, nil // CN is required
		}
		m.step = genSANPreset
		m.optCur = 1 // default: Web preset (handy for dev)
		return m, nil

	case genSANPreset:
		// Resolve the preset
		switch m.optCur {
		case 0: // None
			m.sans = nil
			m.sanDesc = "none"
			m.step = genOrg
			return m, m.newInput("ENTER to skip")
		case 1: // Web
			m.sans = []string{
				"DNS:" + m.cn,
				"DNS:localhost",
				"IP:127.0.0.1",
				"IP:::1",
			}
			m.sanDesc = "web"
			m.step = genOrg
			return m, m.newInput("ENTER to skip")
		case 2: // Wildcard
			m.sans = []string{
				"DNS:" + m.cn,
				"DNS:*." + m.cn,
			}
			m.sanDesc = "wildcard"
			m.step = genOrg
			return m, m.newInput("ENTER to skip")
		case 3: // Wildcard + Web
			m.sans = []string{
				"DNS:" + m.cn,
				"DNS:*." + m.cn,
				"DNS:localhost",
				"IP:127.0.0.1",
				"IP:::1",
			}
			m.sanDesc = "wildcard+web"
			m.step = genOrg
			return m, m.newInput("ENTER to skip")
		case 4: // Custom
			m.step = genSANCustom
			return m, m.newInput("DNS:a.com,DNS:*.a.com,IP:1.2.3.4,email:x@y")
		}
		return m, nil

	case genSANCustom:
		raw := strings.TrimSpace(m.input.Value())
		m.sans = parseCustomSANs(raw)
		if len(m.sans) > 0 {
			m.sanDesc = fmt.Sprintf("custom (%d)", len(m.sans))
		} else {
			m.sanDesc = "none"
		}
		m.step = genOrg
		return m, m.newInput("ENTER to skip")

	case genOrg:
		m.org = m.input.Value()
		m.step = genOU
		return m, m.newInput("ENTER to skip")

	case genOU:
		m.ou = m.input.Value()
		m.step = genCountry
		return m, m.newInput("2 letters, e.g.: US")

	case genCountry:
		m.country = m.input.Value()
		m.step = genState
		return m, m.newInput("ENTER to skip")

	case genState:
		m.state = m.input.Value()
		m.step = genCity
		return m, m.newInput("ENTER to skip")

	case genCity:
		m.city = m.input.Value()
		m.step = genRunning
		return m, m.doGenerate()
	}
	return m, nil
}

func (m *Model) doGenerate() tea.Cmd {
	return func() tea.Msg {
		subject := "/CN=" + m.cn
		if m.org != "" {
			subject += "/O=" + m.org
		}
		if m.ou != "" {
			subject += "/OU=" + m.ou
		}
		if m.country != "" {
			c := m.country
			if len(c) > 2 {
				c = c[:2]
			}
			subject += "/C=" + strings.ToUpper(c)
		}
		if m.state != "" {
			subject += "/ST=" + m.state
		}
		if m.city != "" {
			subject += "/L=" + m.city
		}

		var cmd *exec.Cmd
		if m.algo == "EC" {
			// EC needs process substitution for the curve params: ec:<(openssl ecparam ...)
			// That requires bash, so we build a shell command.
			sanExt := ""
			if len(m.sans) > 0 {
				sanExt = " -addext " + shellQuote("subjectAltName="+strings.Join(m.sans, ","))
			}
			script := fmt.Sprintf(
				"openssl req -x509 -newkey ec:<(openssl ecparam -name %s) -nodes -keyout %s -out %s -days %s -subj %s%s",
				shellQuote(m.curve),
				shellQuote(m.outKey),
				shellQuote(m.outCert),
				m.days,
				shellQuote(subject),
				sanExt,
			)
			cmd = exec.Command("bash", "-c", script)
		} else {
			args := []string{
				"req", "-x509",
				"-newkey", "rsa:" + m.bits, "-nodes",
				"-keyout", m.outKey, "-out", m.outCert,
				"-days", m.days, "-subj", subject,
			}
			if len(m.sans) > 0 {
				args = append(args, "-addext", "subjectAltName="+strings.Join(m.sans, ","))
			}
			cmd = exec.Command("openssl", args...)
		}

		if out, err := cmd.CombinedOutput(); err != nil {
			return genResult{false, "Generation failed: " + err.Error() + "\n" + strings.TrimSpace(string(out))}
		}

		os.Chmod(m.outKey, 0600)
		sanInfo := ""
		if len(m.sans) > 0 {
			sanInfo = fmt.Sprintf("\nSANs: %d entries (%s)", len(m.sans), m.sanDesc)
		}
		var keyInfo string
		if m.algo == "EC" {
			keyInfo = "EC " + m.curve
		} else {
			keyInfo = "RSA " + m.bits
		}
		msg := fmt.Sprintf("Cert: %s\nKey:  %s\nCN: %s | %s days | %s%s",
			m.outCert, m.outKey, m.cn, m.days, keyInfo, sanInfo)
		return genResult{true, msg}
	}
}

// shellQuote safely quotes a string for bash execution.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// parseCustomSANs splits a comma-separated list and normalizes entries.
// Accepts inputs like "a.com, DNS:b.com, IP:1.2.3.4, x@y.com" and prefixes
// bare tokens as DNS:* or email:* when it can tell.
func parseCustomSANs(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		// Already has a known prefix?
		lower := strings.ToLower(p)
		if strings.HasPrefix(lower, "dns:") ||
			strings.HasPrefix(lower, "ip:") ||
			strings.HasPrefix(lower, "email:") ||
			strings.HasPrefix(lower, "uri:") {
			out = append(out, p)
			continue
		}
		// Detect type by content
		if strings.Contains(p, "@") {
			out = append(out, "email:"+p)
		} else if isIPish(p) {
			out = append(out, "IP:"+p)
		} else {
			out = append(out, "DNS:"+p)
		}
	}
	return out
}

// isIPish is a rough check: any string with a digit and a dot or colon.
func isIPish(s string) bool {
	hasDigit := false
	hasSep := false
	for _, r := range s {
		if r >= '0' && r <= '9' {
			hasDigit = true
		}
		if r == '.' || r == ':' {
			hasSep = true
		}
	}
	return hasDigit && hasSep &&
		!strings.ContainsAny(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") ||
		// IPv6 hex letters: allow a-f only
		isIPv6Hex(s)
}

func isIPv6Hex(s string) bool {
	if !strings.Contains(s, ":") {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') ||
			(r >= 'a' && r <= 'f') ||
			(r >= 'A' && r <= 'F') ||
			r == ':') {
			return false
		}
	}
	return true
}

func (m *Model) View() string {
	if m.showHelp {
		return m.renderHelp()
	}
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(ui.Banner())
	b.WriteString("\n  " + ui.TitleStyle.Render("── Generate Self-Signed Certificate ──") + "\n\n")

	// Summary of filled fields
	m.viewSummary(&b)

	switch m.step {
	case genDays:
		b.WriteString("  Validity (days):\n\n")
		for i, d := range []string{"30", "90", "365", "730", "3650"} {
			cursor := "  "
			style := ui.InactiveStyle
			if i == m.optCur {
				cursor = ui.ActiveStyle.Render("➤ ")
				style = ui.ActiveStyle
			}
			b.WriteString(fmt.Sprintf("  %s%s\n", cursor, style.Render(d)))
		}

	case genAlgo:
		b.WriteString("  Key algorithm:\n\n")
		for i, d := range algoLabels {
			cursor := "  "
			style := ui.InactiveStyle
			if i == m.optCur {
				cursor = ui.ActiveStyle.Render("➤ ")
				style = ui.ActiveStyle
			}
			b.WriteString(fmt.Sprintf("  %s%s\n", cursor, style.Render(d)))
		}

	case genBits:
		b.WriteString("  RSA key size:\n\n")
		for i, d := range []string{"2048", "4096"} {
			cursor := "  "
			style := ui.InactiveStyle
			if i == m.optCur {
				cursor = ui.ActiveStyle.Render("➤ ")
				style = ui.ActiveStyle
			}
			b.WriteString(fmt.Sprintf("  %s%s\n", cursor, style.Render(d)))
		}

	case genCurve:
		b.WriteString("  EC curve:\n\n")
		for i, c := range curveOptions {
			cursor := "  "
			style := ui.InactiveStyle
			if i == m.optCur {
				cursor = ui.ActiveStyle.Render("➤ ")
				style = ui.ActiveStyle
			}
			b.WriteString(fmt.Sprintf("  %s%s\n", cursor, style.Render(c.label)))
		}

	case genOutCert:
		b.WriteString("  Certificate file:\n\n")
		b.WriteString("  " + m.input.View() + "\n")

	case genOutKey:
		b.WriteString("  Private key file:\n\n")
		b.WriteString("  " + m.input.View() + "\n")

	case genCN:
		b.WriteString("  Common Name (CN) " + ui.DimStyle.Render("— required") + ":\n\n")
		b.WriteString("  " + m.input.View() + "\n")

	case genSANPreset:
		b.WriteString("  Subject Alternative Names (SAN):\n")
		b.WriteString("  " + ui.DimStyle.Render("Modern browsers require SANs; CN alone is ignored") + "\n\n")
		for i, label := range sanPresetLabels {
			cursor := "  "
			style := ui.InactiveStyle
			if i == m.optCur {
				cursor = ui.ActiveStyle.Render("➤ ")
				style = ui.ActiveStyle
			}
			b.WriteString(fmt.Sprintf("  %s%s\n", cursor, style.Render(label)))
		}

	case genSANCustom:
		b.WriteString("  Custom SANs " + ui.DimStyle.Render("— comma-separated") + ":\n")
		b.WriteString("  " + ui.DimStyle.Render("accepts: DNS:a.com, IP:1.2.3.4, email:x@y  (bare names auto-detected)") + "\n\n")
		b.WriteString("  " + m.input.View() + "\n")

	case genOrg:
		b.WriteString("  Organization (O) " + ui.DimStyle.Render("— optional") + ":\n\n")
		b.WriteString("  " + m.input.View() + "\n")

	case genOU:
		b.WriteString("  Organizational Unit (OU) " + ui.DimStyle.Render("— optional") + ":\n\n")
		b.WriteString("  " + m.input.View() + "\n")

	case genCountry:
		b.WriteString("  Country (C) " + ui.DimStyle.Render("— optional, 2 letters") + ":\n\n")
		b.WriteString("  " + m.input.View() + "\n")

	case genState:
		b.WriteString("  State (ST) " + ui.DimStyle.Render("— optional") + ":\n\n")
		b.WriteString("  " + m.input.View() + "\n")

	case genCity:
		b.WriteString("  City (L) " + ui.DimStyle.Render("— optional") + ":\n\n")
		b.WriteString("  " + m.input.View() + "\n")

	case genRunning:
		b.WriteString("  ⏳ Generating...\n")

	case genDone:
		if m.success {
			b.WriteString(ui.ResultBox(true, "Self-signed certificate generated!", m.result))
		} else {
			b.WriteString(ui.ResultBox(false, "Failed", m.result))
		}
	}

	b.WriteString("\n  " + ui.DimStyle.Render("? help  ENTER confirm/skip  esc back  ctrl+c quit") + "\n")
	return b.String()
}

func (m *Model) renderHelp() string {
	sections := []ui.HelpSection{
		{
			Title: "Steps",
			Entries: []ui.HelpEntry{
				{"enter", "Confirm current step"},
				{"enter (empty)", "Skip optional fields"},
				{"esc", "Back"},
			},
		},
		{
			Title: "Preset shortcuts",
			Entries: []ui.HelpEntry{
				{"↑/↓", "Choose preset / option"},
			},
		},
		ui.CommonHelp(),
	}
	return "\n" + ui.Banner() + "  " + ui.TitleStyle.Render("── Generate Self-Signed Certificate ──") + "\n" + ui.RenderHelp("Generate Self-Signed — Help", sections)
}

func (m *Model) viewSummary(b *strings.Builder) {
	type field struct {
		label string
		value string
		step  genStep
	}
	// Algo summary value depends on which branch was taken
	algoVal := m.algo
	if m.algo == "RSA" && m.bits != "" {
		algoVal = "RSA " + m.bits
	} else if m.algo == "EC" && m.curve != "" {
		algoVal = "EC " + m.curve
	}

	fields := []field{
		{"Days", m.days, genDays},
		{"Algo", algoVal, genAlgo},
		{"Cert", m.outCert, genOutCert},
		{"Key", m.outKey, genOutKey},
		{"CN", m.cn, genCN},
		{"SANs", m.sanDesc, genSANPreset},
		{"O", m.org, genOrg},
		{"OU", m.ou, genOU},
		{"C", m.country, genCountry},
		{"ST", m.state, genState},
		{"L", m.city, genCity},
	}

	hasAny := false
	for _, f := range fields {
		if f.step >= m.step {
			break
		}
		if f.value != "" {
			hasAny = true
			b.WriteString(fmt.Sprintf("  %s %s %s\n",
				ui.DimStyle.Render(fmt.Sprintf("%-5s", f.label)),
				ui.DimStyle.Render("="),
				f.value))
		}
	}
	if hasAny {
		b.WriteString("\n")
	}
}

func sanitize(s string) string {
	r := strings.NewReplacer("*", "_", " ", "_", "/", "_", "\\", "_")
	return r.Replace(s)
}
