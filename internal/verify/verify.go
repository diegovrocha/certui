package verify

import (
	"fmt"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/diegovrocha/certui/internal/history"
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
	showHelp bool
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
		result := "mismatch"
		if msg.success {
			result = "match"
		}
		history.Log("verify_chain",
			history.KV("cert", m.certFile),
			history.KV("intermediate", m.intFile),
			history.KV("ca", m.caFile),
			history.KV("result", result))
		return m, nil
	case tea.KeyMsg:
		// Help overlay on non-input steps
		if m.step == chainAskIntermediate || m.step == chainAskRoot || m.step == chainResult {
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
	if m.showHelp {
		return m.renderHelp()
	}
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

	b.WriteString("\n  " + ui.DimStyle.Render("? help  esc back  ↑/↓ navigate  enter confirm  ctrl+c quit") + "\n")
	return b.String()
}

func (m *ChainModel) renderHelp() string {
	sections := []ui.HelpSection{
		{
			Title: "Flow",
			Entries: []ui.HelpEntry{
				{"1.", "Select end-entity certificate"},
				{"2.", "Optionally select intermediate cert"},
				{"3.", "Optionally select Root CA"},
				{"4.", "Result"},
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
	return "\n" + ui.Banner() + "  " + ui.TitleStyle.Render("── Verify Certificate Chain ──") + "\n" + ui.RenderHelp("Verify Chain — Help", sections)
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
	showHelp bool
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
		result := "mismatch"
		if msg.success {
			result = "match"
		}
		history.Log("verify_cert_key",
			history.KV("cert", m.certFile),
			history.KV("key", m.keyFile),
			history.KV("result", result))
		return m, nil
	case tea.KeyMsg:
		if m.step == ckResult {
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
	if m.showHelp {
		return m.renderHelp()
	}
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

	b.WriteString("\n  " + ui.DimStyle.Render("? help  esc back  ↑/↓ navigate  enter confirm  ctrl+c quit") + "\n")
	return b.String()
}

func (m *CertKeyModel) renderHelp() string {
	sections := []ui.HelpSection{
		{
			Title: "Flow",
			Entries: []ui.HelpEntry{
				{"1.", "Select certificate"},
				{"2.", "Select private key"},
				{"3.", "Result"},
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
	return "\n" + ui.Banner() + "  " + ui.TitleStyle.Render("── Verify Certificate + Key ──") + "\n" + ui.RenderHelp("Verify Cert+Key — Help", sections)
}

// -- Compare Certificates -----------------------------------------

type cmpStep int

const (
	cmpSelectFile1 cmpStep = iota
	cmpPass1
	cmpSelectFile2
	cmpPass2
	cmpAskAnother
	cmpSelectFileN
	cmpPassN
	cmpResultStep
	cmpDiffView
	cmpMatrixView
)

type certField struct {
	label  string
	val1   string
	val2   string
	match  bool
}

// certSummary holds all resolved field values for one certificate.
type certSummary struct {
	file        string
	pem         string // resolved PEM path (temp file if PFX)
	fingerprint string
	serial      string
	subject     string
	issuer      string
	cn          string
	notBefore   string
	notAfter    string
	modulus     string
}

type CompareHashModel struct {
	step    cmpStep
	picker  ui.FilePicker
	input   textinput.Model
	file1   string
	file2   string
	pass1   string
	pass2   string
	pem1    string // resolved PEM path (temp file if PFX)
	pem2    string
	match   bool
	fields  []certField
	err     string

	// Multi-cert support
	files    []string // all file paths collected (>=2)
	pems     []string // resolved PEM paths
	pendingFile string
	optCur   int
	summaries []certSummary
	matrix    [][]bool // matrix[i][j] true when cert i fingerprint == cert j fingerprint
	groups    [][]int  // groups of identical cert indices (by fingerprint)

	showHelp bool
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
		if msg.err == "" {
			result := "mismatch"
			if msg.match {
				result = "match"
			}
			history.Log("compare_certs",
				history.KV("file1", m.file1),
				history.KV("file2", m.file2),
				history.KV("result", result))
		}
		return m, nil
	case multiCompareResult:
		m.summaries = msg.summaries
		m.matrix = msg.matrix
		m.groups = msg.groups
		m.err = msg.err
		m.step = cmpMatrixView
		if msg.err == "" {
			files := make([]string, len(m.files))
			copy(files, m.files)
			history.Log("compare_certs_multi",
				history.KV("count", fmt.Sprintf("%d", len(files))),
				history.KV("files", strings.Join(files, ",")),
				history.KV("groups", fmt.Sprintf("%d", len(msg.groups))))
		}
		return m, nil
	case tea.KeyMsg:
		// Help overlay: only on non-input steps
		if m.step == cmpAskAnother || m.step == cmpResultStep || m.step == cmpDiffView || m.step == cmpMatrixView {
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
			if m.step == cmpDiffView {
				m.step = cmpResultStep
				return m, nil
			}
			return m, nil
		}
		// Result-screen hotkeys
		if m.step == cmpResultStep && m.err == "" {
			switch msg.String() {
			case "d", "D":
				m.step = cmpDiffView
				return m, nil
			}
		}
	}

	switch m.step {
	case cmpSelectFile1, cmpSelectFile2, cmpSelectFileN:
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
				m.files = []string{m.file1}
				m.pems = []string{m.pem1}
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
				m.files = append(m.files, m.file2)
				m.pems = append(m.pems, m.pem2)
				m.step = cmpAskAnother
				m.optCur = 1 // default "No"
				return m, nil
			case cmpSelectFileN:
				m.pendingFile = m.picker.Selected
				if isPFX(m.pendingFile) {
					m.step = cmpPassN
					m.input = textinput.New()
					m.input.Placeholder = "PFX/P12 password"
					m.input.EchoMode = textinput.EchoPassword
					m.input.Focus()
					return m, m.input.Focus()
				}
				m.files = append(m.files, m.pendingFile)
				m.pems = append(m.pems, m.pendingFile)
				m.pendingFile = ""
				m.step = cmpAskAnother
				m.optCur = 1
				return m, nil
			}
		}
		return m, cmd

	case cmpAskAnother:
		if k, ok := msg.(tea.KeyMsg); ok {
			switch k.String() {
			case "up", "k":
				if m.optCur > 0 {
					m.optCur--
				}
			case "down", "j":
				if m.optCur < 1 {
					m.optCur++
				}
			case "y", "Y":
				m.optCur = 0
				m.step = cmpSelectFileN
				m.picker = ui.NewCertFilePicker(fmt.Sprintf("Select certificate #%d", len(m.files)+1))
				return m, nil
			case "n", "N":
				if len(m.files) >= 3 {
					return m, m.doMultiCompare()
				}
				return m, m.doCompare()
			case "enter":
				if m.optCur == 0 { // Yes
					m.step = cmpSelectFileN
					m.picker = ui.NewCertFilePicker(fmt.Sprintf("Select certificate #%d", len(m.files)+1))
					return m, nil
				}
				if len(m.files) >= 3 {
					return m, m.doMultiCompare()
				}
				return m, m.doCompare()
			}
		}
		return m, nil

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
			m.files = []string{m.file1}
			m.pems = []string{m.pem1}
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
			m.files = append(m.files, m.file2)
			m.pems = append(m.pems, m.pem2)
			m.step = cmpAskAnother
			m.optCur = 1
			return m, nil
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd

	case cmpPassN:
		if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" {
			tmp, err := extractPFXtoPEM(m.pendingFile, m.input.Value())
			if err != "" {
				m.err = err
				m.step = cmpResultStep
				return m, nil
			}
			m.files = append(m.files, m.pendingFile)
			m.pems = append(m.pems, tmp)
			m.pendingFile = ""
			m.step = cmpAskAnother
			m.optCur = 1
			return m, nil
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

type multiCompareResult struct {
	summaries []certSummary
	matrix    [][]bool
	groups    [][]int
	err       string
}

func loadSummary(file, pem string) certSummary {
	fp := certField2(pem, "-fingerprint", "")
	if idx := strings.Index(fp, "="); idx >= 0 {
		fp = fp[idx+1:]
	}
	sub := certField2(pem, "-subject", "subject=")
	iss := certField2(pem, "-issuer", "issuer=")
	ser := certField2(pem, "-serial", "serial=")
	nb := certField2(pem, "-startdate", "notBefore=")
	na := certField2(pem, "-enddate", "notAfter=")
	mod := certField2(pem, "-modulus", "Modulus=")
	cn := sub
	for _, part := range strings.Split(sub, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") || strings.HasPrefix(part, "CN =") {
			cn = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(part, "CN="), "CN ="))
			break
		}
	}
	return certSummary{
		file: file, pem: pem, fingerprint: fp, serial: ser,
		subject: sub, issuer: iss, cn: cn, notBefore: nb, notAfter: na,
		modulus: mod,
	}
}

func (m *CompareHashModel) doMultiCompare() tea.Cmd {
	files := make([]string, len(m.files))
	copy(files, m.files)
	pems := make([]string, len(m.pems))
	copy(pems, m.pems)

	return func() tea.Msg {
		n := len(files)
		sums := make([]certSummary, n)
		for i := 0; i < n; i++ {
			sums[i] = loadSummary(files[i], pems[i])
			if sums[i].fingerprint == "" {
				// Cleanup temp files
				for _, p := range pems {
					if strings.HasPrefix(p, "/tmp/certui_cmp_") {
						exec.Command("rm", "-f", p).Run()
					}
				}
				return multiCompareResult{err: fmt.Sprintf("Cannot read certificate: %s", files[i])}
			}
		}
		matrix := make([][]bool, n)
		for i := 0; i < n; i++ {
			matrix[i] = make([]bool, n)
			for j := 0; j < n; j++ {
				matrix[i][j] = sums[i].fingerprint == sums[j].fingerprint
			}
		}
		// Group identical certs by fingerprint
		fpGroup := map[string][]int{}
		order := []string{}
		for i, s := range sums {
			if _, ok := fpGroup[s.fingerprint]; !ok {
				order = append(order, s.fingerprint)
			}
			fpGroup[s.fingerprint] = append(fpGroup[s.fingerprint], i)
		}
		var groups [][]int
		for _, fp := range order {
			groups = append(groups, fpGroup[fp])
		}
		// Cleanup temp files
		for _, p := range pems {
			if strings.HasPrefix(p, "/tmp/certui_cmp_") {
				exec.Command("rm", "-f", p).Run()
			}
		}
		return multiCompareResult{summaries: sums, matrix: matrix, groups: groups}
	}
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
	pem1 := m.pem1
	pem2 := m.pem2
	file1 := m.file1
	file2 := m.file2
	// Store summaries for diff view access
	m.summaries = nil

	return func() tea.Msg {
		s1 := loadSummary(file1, pem1)
		s2 := loadSummary(file2, pem2)

		if s1.fingerprint == "" {
			return compareResult{err: fmt.Sprintf("Cannot read certificate: %s", file1)}
		}
		if s2.fingerprint == "" {
			return compareResult{err: fmt.Sprintf("Cannot read certificate: %s", file2)}
		}

		fields := []certField{
			{"CN", s1.cn, s2.cn, s1.cn == s2.cn},
			{"Fingerprint", s1.fingerprint, s2.fingerprint, s1.fingerprint == s2.fingerprint},
			{"Serial", s1.serial, s2.serial, s1.serial == s2.serial},
			{"Subject", s1.subject, s2.subject, s1.subject == s2.subject},
			{"Issuer", s1.issuer, s2.issuer, s1.issuer == s2.issuer},
			{"Valid from", s1.notBefore, s2.notBefore, s1.notBefore == s2.notBefore},
			{"Valid until", s1.notAfter, s2.notAfter, s1.notAfter == s2.notAfter},
		}

		if s1.modulus != "" && s2.modulus != "" {
			short1, short2 := s1.modulus, s2.modulus
			if len(short1) > 40 {
				short1 = short1[:40] + "..."
			}
			if len(short2) > 40 {
				short2 = short2[:40] + "..."
			}
			fields = append(fields, certField{"Modulus (RSA)", short1, short2, s1.modulus == s2.modulus})
		}

		// Cleanup temp files
		if strings.HasPrefix(pem1, "/tmp/certui_cmp_") {
			exec.Command("rm", "-f", pem1).Run()
		}
		if strings.HasPrefix(pem2, "/tmp/certui_cmp_") {
			exec.Command("rm", "-f", pem2).Run()
		}

		return compareResult{match: s1.fingerprint == s2.fingerprint, fields: fields}
	}
}

func (m *CompareHashModel) View() string {
	if m.showHelp {
		return m.renderHelp()
	}
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

	case cmpAskAnother:
		for i, f := range m.files {
			b.WriteString(fmt.Sprintf("  File %d: %s\n", i+1, ui.ActiveStyle.Render(f)))
		}
		b.WriteString("\n  Add another certificate?\n\n")
		for i, o := range []string{"Yes", "No"} {
			cursor := "  "
			style := ui.InactiveStyle
			if i == m.optCur {
				cursor = ui.ActiveStyle.Render("➤ ")
				style = ui.ActiveStyle
			}
			b.WriteString(fmt.Sprintf("  %s%s\n", cursor, style.Render(o)))
		}

	case cmpSelectFileN:
		for i, f := range m.files {
			b.WriteString(fmt.Sprintf("  File %d: %s\n", i+1, ui.ActiveStyle.Render(f)))
		}
		b.WriteString("\n")
		b.WriteString(m.picker.View())

	case cmpPassN:
		for i, f := range m.files {
			b.WriteString(fmt.Sprintf("  File %d: %s\n", i+1, ui.ActiveStyle.Render(f)))
		}
		b.WriteString(fmt.Sprintf("  Pending: %s\n\n", ui.ActiveStyle.Render(m.pendingFile)))
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

	case cmpDiffView:
		b.WriteString("  " + ui.TitleStyle.Render("Side-by-side diff") + "\n\n")
		b.WriteString(fmt.Sprintf("  File 1: %s\n", ui.ActiveStyle.Render(m.file1)))
		b.WriteString(fmt.Sprintf("  File 2: %s\n\n", ui.ActiveStyle.Render(m.file2)))

		// Column widths
		labelW := 14
		colW := 40
		border := strings.Repeat("─", colW)
		b.WriteString(fmt.Sprintf("  %-*s │ %-*s │ %-*s\n",
			labelW, "Field", colW, "File 1", colW, "File 2"))
		b.WriteString(fmt.Sprintf("  %s─┼─%s─┼─%s\n",
			strings.Repeat("─", labelW), border, border))
		for _, f := range m.fields {
			v1 := truncate(f.val1, colW)
			v2 := truncate(f.val2, colW)
			mark := ui.SuccessStyle.Render("✔")
			style1 := ui.SuccessStyle
			style2 := ui.SuccessStyle
			if !f.match {
				mark = ui.ErrorStyle.Render("✖")
				style1 = ui.ErrorStyle
				style2 = ui.ErrorStyle
			}
			b.WriteString(fmt.Sprintf("  %-*s │ %s │ %s  %s\n",
				labelW, f.label,
				style1.Render(fmt.Sprintf("%-*s", colW, v1)),
				style2.Render(fmt.Sprintf("%-*s", colW, v2)),
				mark))
		}

	case cmpMatrixView:
		if m.err != "" {
			b.WriteString(ui.ResultBox(false, "Error", m.err))
			break
		}
		n := len(m.summaries)
		b.WriteString("  " + ui.TitleStyle.Render(fmt.Sprintf("Comparing %d certificates", n)) + "\n\n")

		// Header row
		b.WriteString(fmt.Sprintf("  %-10s", " "))
		for i := 0; i < n; i++ {
			b.WriteString(fmt.Sprintf(" │ %-7s", fmt.Sprintf("File %d", i+1)))
		}
		b.WriteString("\n  ")
		b.WriteString(strings.Repeat("─", 10))
		for i := 0; i < n; i++ {
			b.WriteString("─┼─" + strings.Repeat("─", 7))
		}
		b.WriteString("\n")

		for i := 0; i < n; i++ {
			b.WriteString(fmt.Sprintf("  %-10s", fmt.Sprintf("File %d", i+1)))
			for j := 0; j < n; j++ {
				var cell string
				if i == j {
					cell = ui.DimStyle.Render("   -   ")
				} else if m.matrix[i][j] {
					cell = ui.SuccessStyle.Render("   ✔   ")
				} else {
					cell = ui.ErrorStyle.Render("   ✖   ")
				}
				b.WriteString(" │ " + cell)
			}
			b.WriteString("\n")
		}

		b.WriteString("\n")
		for i, s := range m.summaries {
			b.WriteString(fmt.Sprintf("  File %d: %s  %s\n", i+1, ui.ActiveStyle.Render(s.file), ui.DimStyle.Render("("+s.cn+")")))
		}

		// Groups of identical certs
		b.WriteString("\n")
		for gi, g := range m.groups {
			if len(g) >= 3 {
				names := make([]string, len(g))
				for k, idx := range g {
					names[k] = fmt.Sprintf("File %d", idx+1)
				}
				b.WriteString("  " + ui.SuccessStyle.Render(fmt.Sprintf("✔ All match: %s", strings.Join(names, ", "))) + "\n")
			} else if len(g) == 2 {
				b.WriteString("  " + ui.SuccessStyle.Render(fmt.Sprintf("✔ Group %d: File %d and File %d identical", gi+1, g[0]+1, g[1]+1)) + "\n")
			}
		}
		if len(m.groups) == n {
			b.WriteString("  " + ui.ErrorStyle.Render("✖ All certificates differ") + "\n")
		}
	}

	// Footer varies by step
	switch m.step {
	case cmpResultStep:
		if m.err == "" {
			b.WriteString("\n  " + ui.DimStyle.Render("? help  d diff view  esc back  ctrl+c quit") + "\n")
		} else {
			b.WriteString("\n  " + ui.DimStyle.Render("? help  esc back  ctrl+c quit") + "\n")
		}
	case cmpDiffView:
		b.WriteString("\n  " + ui.DimStyle.Render("? help  esc back  ctrl+c quit") + "\n")
	case cmpAskAnother:
		b.WriteString("\n  " + ui.DimStyle.Render("? help  y add  n compare  ↑/↓ enter  esc back  ctrl+c quit") + "\n")
	case cmpMatrixView:
		b.WriteString("\n  " + ui.DimStyle.Render("? help  esc back  ctrl+c quit") + "\n")
	default:
		b.WriteString("\n  " + ui.DimStyle.Render("esc back  enter confirm  ctrl+c quit") + "\n")
	}
	return b.String()
}

func (m *CompareHashModel) renderHelp() string {
	sections := []ui.HelpSection{
		{
			Title: "Flow",
			Entries: []ui.HelpEntry{
				{"1.", "Select certificate 1"},
				{"2.", "Select certificate 2"},
				{"3.", "Prompt: add another?"},
				{"4.", "Result"},
			},
		},
		{
			Title: "Result",
			Entries: []ui.HelpEntry{
				{"d", "Diff view (2 certs)"},
				{"matrix", "Auto shown for 3+ certs"},
			},
		},
		ui.CommonHelp(),
	}
	return "\n" + ui.Banner() + "  " + ui.TitleStyle.Render("── Compare Certificates ──") + "\n" + ui.RenderHelp("Compare Certs — Help", sections)
}

// truncate returns s limited to n runes, adding an ellipsis if shortened.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}
