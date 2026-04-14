package verify

import (
	"fmt"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/diegovrocha/certui/internal/ui"
)

// -- Verify Chain -------------------------------------------------

type chainStep int

const (
	chainSelectCert chainStep = iota
	chainAskIntermediate
	chainSelectIntermediate
	chainAskRoot
	chainSelectRoot
	chainResult
)

type ChainModel struct {
	step     chainStep
	picker   ui.FilePicker
	certFile string
	intFile  string
	caFile   string
	optCur   int
	result   string
	success  bool
}

func NewChain() tea.Model {
	return &ChainModel{
		step:   chainSelectCert,
		picker: ui.NewCertOnlyPicker("Select the certificate to verify"),
	}
}

func (m *ChainModel) Init() tea.Cmd { return nil }

func (m *ChainModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case verifyResult:
		m.success = msg.success
		m.result = msg.message
		m.step = chainResult
		return m, nil
	case tea.KeyMsg:
		if msg.String() == "esc" {
			return m, nil
		}
		switch m.step {
		case chainSelectCert, chainSelectIntermediate, chainSelectRoot:
			var cmd tea.Cmd
			m.picker, cmd = m.picker.Update(msg)
			if m.picker.Done {
				return m.advancePicker()
			}
			return m, cmd

		case chainAskIntermediate, chainAskRoot:
			switch msg.String() {
			case "up", "k":
				if m.optCur > 0 {
					m.optCur--
				}
			case "down", "j":
				if m.optCur < 1 {
					m.optCur++
				}
			case "enter":
				return m.advanceChoice()
			}
		}
	}
	return m, nil
}

type verifyResult struct {
	success bool
	message string
}

func (m *ChainModel) advancePicker() (tea.Model, tea.Cmd) {
	switch m.step {
	case chainSelectCert:
		m.certFile = m.picker.Selected
		m.step = chainAskIntermediate
		m.optCur = 0
	case chainSelectIntermediate:
		m.intFile = m.picker.Selected
		m.step = chainAskRoot
		m.optCur = 0
	case chainSelectRoot:
		m.caFile = m.picker.Selected
		return m, m.doVerify()
	}
	return m, nil
}

func (m *ChainModel) advanceChoice() (tea.Model, tea.Cmd) {
	switch m.step {
	case chainAskIntermediate:
		if m.optCur == 0 { // Yes
			m.step = chainSelectIntermediate
			m.picker = ui.NewCertOnlyPicker("Select the intermediate certificate")
		} else {
			m.step = chainAskRoot
			m.optCur = 0
		}
	case chainAskRoot:
		if m.optCur == 1 { // Custom file
			m.step = chainSelectRoot
			m.picker = ui.NewCertOnlyPicker("Select the Root CA")
		} else {
			return m, m.doVerify()
		}
	}
	return m, nil
}

func (m *ChainModel) doVerify() tea.Cmd {
	return func() tea.Msg {
		args := []string{"verify"}
		if m.intFile != "" {
			args = append(args, "-untrusted", m.intFile)
		}
		if m.caFile != "" {
			args = append(args, "-CAfile", m.caFile)
		}
		args = append(args, m.certFile)

		out, err := exec.Command("openssl", args...).CombinedOutput()
		if err != nil {
			return verifyResult{false, strings.TrimSpace(string(out))}
		}
		return verifyResult{true, strings.TrimSpace(string(out))}
	}
}

func (m *ChainModel) View() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(ui.Banner())
	b.WriteString("\n  " + ui.TitleStyle.Render("── Verify Certificate Chain ──") + "\n\n")

	switch m.step {
	case chainSelectCert, chainSelectIntermediate, chainSelectRoot:
		b.WriteString(m.picker.View())

	case chainAskIntermediate:
		b.WriteString("  Do you have separate intermediate certificate(s)?\n\n")
		for i, o := range []string{"Yes", "No"} {
			cursor := "  "
			style := ui.InactiveStyle
			if i == m.optCur {
				cursor = ui.ActiveStyle.Render("➤ ")
				style = ui.ActiveStyle
			}
			b.WriteString(fmt.Sprintf("  %s%s\n", cursor, style.Render(o)))
		}

	case chainAskRoot:
		b.WriteString("  Which Root CA to use?\n\n")
		for i, o := range []string{"System CA (default)", "Custom CA file"} {
			cursor := "  "
			style := ui.InactiveStyle
			if i == m.optCur {
				cursor = ui.ActiveStyle.Render("➤ ")
				style = ui.ActiveStyle
			}
			b.WriteString(fmt.Sprintf("  %s%s\n", cursor, style.Render(o)))
		}

	case chainResult:
		if m.success {
			b.WriteString(ui.ResultBox(true, "Chain valid!", m.result))
		} else {
			b.WriteString(ui.ResultBox(false, "Chain invalid", m.result))
		}
	}

	b.WriteString("\n  " + ui.DimStyle.Render("esc back  ↑/↓ navigate  enter confirm  ctrl+c quit") + "\n")
	return b.String()
}

// -- Verify Cert + Key --------------------------------------------

type certKeyStep int

const (
	ckSelectCert certKeyStep = iota
	ckSelectKey
	ckResult
)

type CertKeyModel struct {
	step     certKeyStep
	picker   ui.FilePicker
	certFile string
	keyFile  string
	result   string
	match    bool
}

func NewCertKey() tea.Model {
	return &CertKeyModel{
		step:   ckSelectCert,
		picker: ui.NewCertOnlyPicker("Select the certificate"),
	}
}

func (m *CertKeyModel) Init() tea.Cmd { return nil }

func (m *CertKeyModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case verifyResult:
		m.match = msg.success
		m.result = msg.message
		m.step = ckResult
		return m, nil
	case tea.KeyMsg:
		if msg.String() == "esc" {
			return m, nil
		}
	}

	if m.step == ckSelectCert || m.step == ckSelectKey {
		var cmd tea.Cmd
		m.picker, cmd = m.picker.Update(msg)
		if m.picker.Done {
			switch m.step {
			case ckSelectCert:
				m.certFile = m.picker.Selected
				m.step = ckSelectKey
				m.picker = ui.NewKeyPicker("Select the private key")
			case ckSelectKey:
				m.keyFile = m.picker.Selected
				return m, m.doCompare()
			}
		}
		return m, cmd
	}

	return m, nil
}

func (m *CertKeyModel) doCompare() tea.Cmd {
	return func() tea.Msg {
		certMod, _ := exec.Command("openssl", "x509", "-in", m.certFile, "-noout", "-modulus").Output()
		keyMod, _ := exec.Command("openssl", "rsa", "-in", m.keyFile, "-noout", "-modulus").Output()

		cm := strings.TrimSpace(string(certMod))
		km := strings.TrimSpace(string(keyMod))

		if cm == "" {
			certMod, _ = exec.Command("openssl", "x509", "-in", m.certFile, "-inform", "DER", "-noout", "-modulus").Output()
			cm = strings.TrimSpace(string(certMod))
		}

		if km == "" {
			certPub, _ := exec.Command("openssl", "x509", "-in", m.certFile, "-noout", "-pubkey").Output()
			keyPub, _ := exec.Command("openssl", "pkey", "-in", m.keyFile, "-pubout").Output()
			if len(certPub) > 0 && len(keyPub) > 0 && string(certPub) == string(keyPub) {
				return verifyResult{true, "Type: EC (Elliptic Curve)"}
			}
			if len(certPub) > 0 && len(keyPub) > 0 {
				return verifyResult{false, "Type: EC — keys do not match"}
			}
			return verifyResult{false, "Could not read the key"}
		}

		if cm == km {
			short := strings.TrimPrefix(cm, "Modulus=")
			if len(short) > 32 {
				short = short[:32] + "..."
			}
			return verifyResult{true, fmt.Sprintf("Type: RSA | Modulus: %s", short)}
		}
		return verifyResult{false, "Modulus mismatch"}
	}
}

func (m *CertKeyModel) View() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(ui.Banner())
	b.WriteString("\n  " + ui.TitleStyle.Render("── Verify Certificate + Key ──") + "\n\n")

	switch m.step {
	case ckSelectCert, ckSelectKey:
		b.WriteString(m.picker.View())
	case ckResult:
		if m.match {
			b.WriteString(ui.ResultBox(true, "Certificate and key MATCH!",
				"Cert: "+m.certFile, "Key:  "+m.keyFile, m.result))
		} else {
			b.WriteString(ui.ResultBox(false, "Certificate and key DO NOT match",
				"Cert: "+m.certFile, "Key:  "+m.keyFile, m.result))
		}
	}

	b.WriteString("\n  " + ui.DimStyle.Render("esc back  ↑/↓ navigate  enter confirm  ctrl+c quit") + "\n")
	return b.String()
}

// -- Compare Certificates -----------------------------------------

type cmpStep int

const (
	cmpSelectFile1 cmpStep = iota
	cmpPass1
	cmpSelectFile2
	cmpPass2
	cmpResultStep
)

type certField struct {
	label  string
	val1   string
	val2   string
	match  bool
}

type CompareHashModel struct {
	step   cmpStep
	picker ui.FilePicker
	input  textinput.Model
	file1  string
	file2  string
	pass1  string
	pass2  string
	pem1   string // resolved PEM path (temp file if PFX)
	pem2   string
	match  bool
	fields []certField
	err    string
}

func NewCompareHash() tea.Model {
	return &CompareHashModel{
		step:   cmpSelectFile1,
		picker: ui.NewCertFilePicker("Select the first certificate"),
	}
}

func (m *CompareHashModel) Init() tea.Cmd { return nil }

func isPFX(file string) bool {
	ext := strings.ToLower(file)
	return strings.HasSuffix(ext, ".pfx") || strings.HasSuffix(ext, ".p12")
}

func (m *CompareHashModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case compareResult:
		m.match = msg.match
		m.fields = msg.fields
		m.err = msg.err
		m.step = cmpResultStep
		return m, nil
	case tea.KeyMsg:
		if msg.String() == "esc" {
			return m, nil
		}
	}

	switch m.step {
	case cmpSelectFile1, cmpSelectFile2:
		var cmd tea.Cmd
		m.picker, cmd = m.picker.Update(msg)
		if m.picker.Done {
			switch m.step {
			case cmpSelectFile1:
				m.file1 = m.picker.Selected
				if isPFX(m.file1) {
					m.step = cmpPass1
					m.input = textinput.New()
					m.input.Placeholder = "PFX/P12 password"
					m.input.EchoMode = textinput.EchoPassword
					m.input.Focus()
					return m, m.input.Focus()
				}
				m.pem1 = m.file1
				m.step = cmpSelectFile2
				m.picker = ui.NewCertFilePicker("Select the second certificate")
			case cmpSelectFile2:
				m.file2 = m.picker.Selected
				if isPFX(m.file2) {
					m.step = cmpPass2
					m.input = textinput.New()
					m.input.Placeholder = "PFX/P12 password"
					m.input.EchoMode = textinput.EchoPassword
					m.input.Focus()
					return m, m.input.Focus()
				}
				m.pem2 = m.file2
				return m, m.doCompare()
			}
		}
		return m, cmd

	case cmpPass1:
		if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" {
			m.pass1 = m.input.Value()
			tmp, err := extractPFXtoPEM(m.file1, m.pass1)
			if err != "" {
				m.err = err
				m.step = cmpResultStep
				return m, nil
			}
			m.pem1 = tmp
			m.step = cmpSelectFile2
			m.picker = ui.NewCertFilePicker("Select the second certificate")
			return m, nil
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd

	case cmpPass2:
		if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" {
			m.pass2 = m.input.Value()
			tmp, err := extractPFXtoPEM(m.file2, m.pass2)
			if err != "" {
				m.err = err
				m.step = cmpResultStep
				return m, nil
			}
			m.pem2 = tmp
			return m, m.doCompare()
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}

	return m, nil
}

type compareResult struct {
	match  bool
	fields []certField
	err    string
}

func extractPFXtoPEM(file, password string) (pemPath string, errMsg string) {
	tmp := fmt.Sprintf("/tmp/certui_cmp_%d.pem", len(file))
	legacy := detectLegacy2()
	args := append([]string{"pkcs12", "-in", file, "-out", tmp,
		"-passin", "pass:" + password, "-nokeys", "-clcerts"}, legacy...)
	if err := exec.Command("openssl", args...).Run(); err != nil {
		return "", fmt.Sprintf("Failed to read %s: wrong password or invalid PFX", file)
	}
	return tmp, ""
}

func detectLegacy2() []string {
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

func certField2(file, flag, prefix string) string {
	out, _ := exec.Command("openssl", "x509", "-in", file, "-noout", flag).Output()
	if len(out) == 0 {
		out, _ = exec.Command("openssl", "x509", "-in", file, "-inform", "DER", "-noout", flag).Output()
	}
	s := strings.TrimSpace(string(out))
	if prefix != "" {
		s = strings.TrimPrefix(s, prefix)
	}
	return strings.TrimSpace(s)
}

func (m *CompareHashModel) doCompare() tea.Cmd {
	return func() tea.Msg {
		f1 := m.pem1
		f2 := m.pem2

		fp1 := certField2(f1, "-fingerprint", "")
		fp2 := certField2(f2, "-fingerprint", "")
		// Extract just the hash after "="
		if idx := strings.Index(fp1, "="); idx >= 0 { fp1 = fp1[idx+1:] }
		if idx := strings.Index(fp2, "="); idx >= 0 { fp2 = fp2[idx+1:] }

		if fp1 == "" {
			return compareResult{err: fmt.Sprintf("Cannot read certificate: %s", m.file1)}
		}
		if fp2 == "" {
			return compareResult{err: fmt.Sprintf("Cannot read certificate: %s", m.file2)}
		}

		sub1 := certField2(f1, "-subject", "subject=")
		sub2 := certField2(f2, "-subject", "subject=")
		ser1 := certField2(f1, "-serial", "serial=")
		ser2 := certField2(f2, "-serial", "serial=")
		exp1 := certField2(f1, "-enddate", "notAfter=")
		exp2 := certField2(f2, "-enddate", "notAfter=")

		mod1 := certField2(f1, "-modulus", "Modulus=")
		mod2 := certField2(f2, "-modulus", "Modulus=")

		fields := []certField{
			{"Fingerprint", fp1, fp2, fp1 == fp2},
			{"Serial", ser1, ser2, ser1 == ser2},
			{"Subject", sub1, sub2, sub1 == sub2},
			{"Expires", exp1, exp2, exp1 == exp2},
		}

		if mod1 != "" && mod2 != "" {
			short1, short2 := mod1, mod2
			if len(short1) > 40 { short1 = short1[:40] + "..." }
			if len(short2) > 40 { short2 = short2[:40] + "..." }
			fields = append(fields, certField{"Modulus (RSA)", short1, short2, mod1 == mod2})
		}

		// Cleanup temp files
		if strings.HasPrefix(m.pem1, "/tmp/certui_cmp_") {
			exec.Command("rm", "-f", m.pem1).Run()
		}
		if strings.HasPrefix(m.pem2, "/tmp/certui_cmp_") {
			exec.Command("rm", "-f", m.pem2).Run()
		}

		return compareResult{match: fp1 == fp2, fields: fields}
	}
}

func (m *CompareHashModel) View() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(ui.Banner())
	b.WriteString("\n  " + ui.TitleStyle.Render("── Compare Certificates ──") + "\n\n")

	switch m.step {
	case cmpSelectFile1:
		b.WriteString(m.picker.View())

	case cmpPass1:
		b.WriteString(fmt.Sprintf("  File 1: %s\n\n", ui.ActiveStyle.Render(m.file1)))
		b.WriteString("  🔑 PFX/P12 password:\n\n")
		b.WriteString("  " + m.input.View() + "\n")

	case cmpSelectFile2:
		b.WriteString(fmt.Sprintf("  File 1: %s\n\n", ui.ActiveStyle.Render(m.file1)))
		b.WriteString(m.picker.View())

	case cmpPass2:
		b.WriteString(fmt.Sprintf("  File 1: %s\n", ui.ActiveStyle.Render(m.file1)))
		b.WriteString(fmt.Sprintf("  File 2: %s\n\n", ui.ActiveStyle.Render(m.file2)))
		b.WriteString("  🔑 PFX/P12 password:\n\n")
		b.WriteString("  " + m.input.View() + "\n")

	case cmpResultStep:
		if m.err != "" {
			b.WriteString(ui.ResultBox(false, "Error", m.err))
		} else {
			b.WriteString(fmt.Sprintf("  File 1: %s\n", ui.ActiveStyle.Render(m.file1)))
			b.WriteString(fmt.Sprintf("  File 2: %s\n\n", ui.ActiveStyle.Render(m.file2)))

			for _, f := range m.fields {
				icon := ui.SuccessStyle.Render("✔")
				status := ui.SuccessStyle.Render("MATCH")
				if !f.match {
					icon = ui.ErrorStyle.Render("✖")
					status = ui.ErrorStyle.Render("DIFFER")
				}
				b.WriteString(fmt.Sprintf("  %s %s  %s\n", icon, ui.TitleStyle.Render(f.label), status))
				b.WriteString(fmt.Sprintf("    1: %s\n", f.val1))
				b.WriteString(fmt.Sprintf("    2: %s\n\n", f.val2))
			}

			if m.match {
				b.WriteString("  " + ui.SuccessStyle.Render("✔ Same certificate (fingerprint match)") + "\n")
			} else {
				b.WriteString("  " + ui.ErrorStyle.Render("✖ Different certificates") + "\n")
			}
		}
	}

	b.WriteString("\n  " + ui.DimStyle.Render("esc back  enter confirm  ctrl+c quit") + "\n")
	return b.String()
}
