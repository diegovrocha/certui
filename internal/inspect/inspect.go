package inspect

import (
	"fmt"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/diegovrocha/certui/internal/ui"
)

type step int

const (
	stepFile step = iota
	stepPassword
	stepResult
)

type CertInfo struct {
	CN, Subject, Issuer            string
	NotBefore, NotAfter            string
	Serial, Fingerprint            string
	SigAlg, KeyType, KeySize       string
	SANs                           string
	KeyUsage, ExtKeyUsage          string
	BasicConstraints               string
	CertType, Valid, ValidColor    string

	// Full view fields
	Version                string
	AuthorityKeyID         string
	SubjectKeyID           string
	AIACAIssuers           string
	AIAOCSP                string
	CRLDistPoints          string
	CertPoliciesOID        string
	CertPoliciesCPS        string
	SignatureValue         string
}

type Model struct {
	step     step
	picker   ui.FilePicker
	passIn   textinput.Model
	infile   string
	password string
	needPass bool
	certs    []CertInfo
	scroll   int
	height   int
	err      string
	fullView bool
}

func New() tea.Model {
	return &Model{
		step:   stepFile,
		picker: ui.NewCertFilePicker("Select the certificate"),
	}
}

func (m *Model) Init() tea.Cmd { return textinput.Blink }

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.height = msg.Height
		return m, nil
	case inspectResult:
		m.certs = msg.certs
		m.err = msg.err
		m.step = stepResult
		m.scroll = 0
		return m, nil
	case tea.KeyMsg:
		if msg.String() == "esc" {
			if m.step == stepResult {
				m.step = stepFile
				m.certs = nil
				m.err = ""
				m.picker = ui.NewCertFilePicker("Select the certificate")
				return m, nil
			}
			return m, nil
		}
		if m.step == stepResult {
			switch msg.String() {
			case "up", "k":
				if m.scroll > 0 { m.scroll-- }
			case "down", "j":
				m.scroll++
			case "f":
				m.fullView = !m.fullView
			case "n", "N":
				// Inspect another certificate without going back to the menu
				m.step = stepFile
				m.certs = nil
				m.err = ""
				m.scroll = 0
				m.fullView = false
				m.picker = ui.NewCertFilePicker("Select the certificate")
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
			ext := strings.ToLower(m.infile[strings.LastIndex(m.infile, ".")+1:])
			if ext == "pfx" || ext == "p12" {
				m.needPass = true
				m.step = stepPassword
				m.passIn = textinput.New()
				m.passIn.Placeholder = "PFX/P12 password"
				m.passIn.EchoMode = textinput.EchoPassword
				m.passIn.Focus()
				return m, m.passIn.Focus()
			}
			return m, m.doInspect()
		}
		return m, cmd

	case stepPassword:
		if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" {
			m.password = m.passIn.Value()
			return m, m.doInspect()
		}
		var cmd tea.Cmd
		m.passIn, cmd = m.passIn.Update(msg)
		return m, cmd
	}

	return m, nil
}

type inspectResult struct {
	certs []CertInfo
	err   string
}

func (m *Model) doInspect() tea.Cmd {
	return func() tea.Msg {
		pemFile := m.infile
		ext := strings.ToLower(pemFile[strings.LastIndex(pemFile, ".")+1:])

		switch ext {
		case "pfx", "p12":
			tmp := "/tmp/certui_inspect.pem"
			args := []string{"pkcs12", "-in", m.infile, "-out", tmp,
				"-passin", "pass:" + m.password, "-nokeys", "-clcerts"}
			legacy := detectLegacy()
			args = append(args, legacy...)
			if err := runCmd("openssl", args...); err != nil {
				return inspectResult{err: "Failed to read certificate: " + err.Error()}
			}
			pemFile = tmp
		case "cer", "der":
			if !hasPEMMarker(m.infile) {
				tmp := "/tmp/certui_inspect_der.pem"
				if err := runCmd("openssl", "x509", "-in", m.infile, "-inform", "DER",
					"-out", tmp, "-outform", "PEM"); err != nil {
					return inspectResult{err: "Unrecognized format"}
				}
				pemFile = tmp
			}
		case "key":
			return inspectResult{err: ".key file contains only a private key"}
		case "pem", "crt":
			if hasPrivateKeyOnly(m.infile) {
				return inspectResult{err: "File contains only a private key"}
			}
		}

		certs := splitPEM(pemFile)
		if len(certs) == 0 {
			return inspectResult{err: "No certificates found"}
		}

		var infos []CertInfo
		for i, certFile := range certs {
			info := extractInfo(certFile, i+1, len(certs))
			if info != nil {
				infos = append(infos, *info)
			}
		}
		if len(infos) == 0 {
			return inspectResult{err: "No valid certificates found"}
		}
		return inspectResult{certs: infos}
	}
}

func (m *Model) View() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(ui.Banner())
	b.WriteString("\n  " + ui.TitleStyle.Render("── Inspect Certificate ──") + "\n\n")

	switch m.step {
	case stepFile:
		b.WriteString(m.picker.View())

	case stepPassword:
		b.WriteString(fmt.Sprintf("  File: %s\n\n", ui.ActiveStyle.Render(m.infile)))
		b.WriteString("  🔑 PFX/P12 password:\n\n")
		b.WriteString("  " + m.passIn.View() + "\n")

	case stepResult:
		if m.err != "" {
			b.WriteString(ui.ResultBox(false, "Error", m.err))
		} else {
			// Build all cert lines
			var certLines []string
			for _, cert := range m.certs {
				text := formatCert(cert, m.fullView)
				lines := strings.Split(text, "\n")
				certLines = append(certLines, lines...)
			}

			// Fixed overhead: banner(~10) + title(2) + footer(3) = 15 lines
			viewHeight := m.height - 15
			if viewHeight < 5 {
				viewHeight = 20
			}

			totalLines := len(certLines)

			if totalLines <= viewHeight {
				// Everything fits — no scroll needed
				m.scroll = 0
				for _, line := range certLines {
					b.WriteString(line)
					b.WriteString("\n")
				}
			} else {
				// Clamp scroll
				maxScroll := totalLines - viewHeight
				if m.scroll > maxScroll {
					m.scroll = maxScroll
				}
				if m.scroll < 0 {
					m.scroll = 0
				}

				end := m.scroll + viewHeight
				if end > totalLines {
					end = totalLines
				}

				if m.scroll > 0 {
					b.WriteString(fmt.Sprintf("  %s\n", ui.DimStyle.Render(fmt.Sprintf("  ↑ %d lines above", m.scroll))))
				}

				for i := m.scroll; i < end; i++ {
					b.WriteString(certLines[i])
					b.WriteString("\n")
				}

				remaining := totalLines - end
				if remaining > 0 {
					b.WriteString(fmt.Sprintf("  %s\n", ui.DimStyle.Render(fmt.Sprintf("  ↓ %d lines below", remaining))))
				}
			}
		}
	}

	if m.step == stepResult && m.err == "" {
		b.WriteString("\n  " + ui.DimStyle.Render("↑/↓ scroll  n inspect another  f toggle full view  esc back  ctrl+c quit") + "\n")
	} else {
		b.WriteString("\n  " + ui.DimStyle.Render("esc back  ↑/↓ navigate  enter confirm  ctrl+c quit") + "\n")
	}
	return b.String()
}

func formatCert(c CertInfo, full bool) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("  %s\n\n", ui.TitleStyle.Render(c.CertType)))

	// Identity
	b.WriteString(fmt.Sprintf("    %-16s %s\n", "CN:", c.CN))
	b.WriteString(fmt.Sprintf("    %-16s %s\n", "Subject:", c.Subject))
	b.WriteString(fmt.Sprintf("    %-16s %s\n", "Issuer:", c.Issuer))
	b.WriteString("\n")

	// Validity
	b.WriteString(fmt.Sprintf("    %-16s %s\n", "Valid from:", c.NotBefore))
	b.WriteString(fmt.Sprintf("    %-16s %s\n", "Valid until:", c.NotAfter))
	b.WriteString("\n")

	// Identifiers
	b.WriteString(fmt.Sprintf("    %-16s %s\n", "Serial:", c.Serial))
	b.WriteString(fmt.Sprintf("    %-16s %s\n", "Fingerprint:", c.Fingerprint))
	b.WriteString(fmt.Sprintf("    %-16s %s\n", "Signature:", c.SigAlg))
	b.WriteString(fmt.Sprintf("    %-16s %s %s\n", "Public key:", c.KeyType, c.KeySize))
	b.WriteString("\n")

	// Extensions (only show if present)
	if c.BasicConstraints != "" {
		b.WriteString(fmt.Sprintf("    %-16s %s\n", "CA:", c.BasicConstraints))
	}
	if c.KeyUsage != "" {
		b.WriteString(fmt.Sprintf("    %-16s %s\n", "Key Usage:", c.KeyUsage))
	}
	if c.ExtKeyUsage != "" {
		b.WriteString(fmt.Sprintf("    %-16s %s\n", "Ext Key Usage:", c.ExtKeyUsage))
	}
	if c.SANs != "" {
		b.WriteString(fmt.Sprintf("    %-16s %s\n", "SANs:", c.SANs))
	}

	// Full view fields
	if full {
		b.WriteString("\n")
		if c.Version != "" {
			b.WriteString(fmt.Sprintf("    %-16s %s\n", "Version:", c.Version))
		}
		if c.AuthorityKeyID != "" {
			b.WriteString(fmt.Sprintf("    %-16s %s\n", "Auth Key ID:", c.AuthorityKeyID))
		}
		if c.SubjectKeyID != "" {
			b.WriteString(fmt.Sprintf("    %-16s %s\n", "Subj Key ID:", c.SubjectKeyID))
		}
		if c.AIACAIssuers != "" {
			b.WriteString(fmt.Sprintf("    %-16s %s\n", "CA Issuers:", c.AIACAIssuers))
		}
		if c.AIAOCSP != "" {
			b.WriteString(fmt.Sprintf("    %-16s %s\n", "OCSP:", c.AIAOCSP))
		}
		if c.CRLDistPoints != "" {
			b.WriteString(fmt.Sprintf("    %-16s %s\n", "CRL Dist:", c.CRLDistPoints))
		}
		if c.CertPoliciesOID != "" {
			b.WriteString(fmt.Sprintf("    %-16s %s\n", "Policy OID:", c.CertPoliciesOID))
		}
		if c.CertPoliciesCPS != "" {
			b.WriteString(fmt.Sprintf("    %-16s %s\n", "CPS URL:", c.CertPoliciesCPS))
		}
		if c.SignatureValue != "" {
			b.WriteString(fmt.Sprintf("    %-16s %s\n", "Sig Value:", c.SignatureValue))
		}
	}

	b.WriteString("\n")
	switch c.ValidColor {
	case "green":
		b.WriteString(fmt.Sprintf("    %s\n", ui.SuccessStyle.Render("✔ "+c.Valid)))
	case "red":
		b.WriteString(fmt.Sprintf("    %s\n", ui.ErrorStyle.Render("✖ "+c.Valid)))
	case "yellow":
		b.WriteString(fmt.Sprintf("    %s\n", ui.WarnStyle.Render("⚠ "+c.Valid)))
	}
	return b.String()
}

// helpers

func hasPEMMarker(file string) bool {
	return exec.Command("grep", "-q", "BEGIN CERTIFICATE", file).Run() == nil
}

func hasPrivateKeyOnly(file string) bool {
	hasKey := exec.Command("grep", "-q", "PRIVATE KEY", file).Run() == nil
	hasCert := exec.Command("grep", "-q", "BEGIN CERTIFICATE", file).Run() == nil
	return hasKey && !hasCert
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

func splitPEM(file string) []string {
	data, err := exec.Command("cat", file).Output()
	if err != nil {
		return nil
	}

	var certs []string
	content := string(data)
	for {
		start := strings.Index(content, "-----BEGIN CERTIFICATE-----")
		if start == -1 {
			break
		}
		end := strings.Index(content[start:], "-----END CERTIFICATE-----")
		if end == -1 {
			break
		}
		end += start + len("-----END CERTIFICATE-----")

		tmp := fmt.Sprintf("/tmp/certui_cert_%d.pem", len(certs))
		if err := exec.Command("bash", "-c",
			fmt.Sprintf("cat > %s << 'CERTEOF'\n%s\nCERTEOF", tmp, content[start:end])).Run(); err != nil {
			continue
		}
		certs = append(certs, tmp)
		content = content[end:]
	}
	return certs
}

func extractInfo(certFile string, num, total int) *CertInfo {
	if exec.Command("openssl", "x509", "-in", certFile, "-noout").Run() != nil {
		return nil
	}

	get := func(flag string) string {
		out, _ := exec.Command("openssl", "x509", "-in", certFile, "-noout", flag).Output()
		return strings.TrimSpace(string(out))
	}

	// Get the full text to extract extensions
	fullText, _ := exec.Command("openssl", "x509", "-in", certFile, "-noout", "-text").Output()
	fullStr := string(fullText)

	subject := strings.TrimPrefix(get("-subject"), "subject=")
	subject = strings.TrimSpace(subject)
	issuer := strings.TrimPrefix(get("-issuer"), "issuer=")
	issuer = strings.TrimSpace(issuer)
	notBefore := strings.TrimPrefix(get("-startdate"), "notBefore=")
	notAfter := strings.TrimPrefix(get("-enddate"), "notAfter=")
	serial := strings.TrimPrefix(get("-serial"), "serial=")
	fp := get("-fingerprint")
	if idx := strings.Index(fp, "="); idx >= 0 {
		fp = fp[idx+1:]
	}

	cn := extractCN(subject)

	// Signature algorithm
	sigAlg := extractField(fullStr, "Signature Algorithm:")

	// Key type and size
	keyType := "RSA"
	keySize := ""
	if pk := extractField(fullStr, "Public-Key:"); pk != "" {
		keySize = pk
		if strings.Contains(strings.ToLower(fullStr), "ec public key") || strings.Contains(strings.ToLower(fullStr), "id-ecpublickey") {
			keyType = "EC"
		}
	}

	// SANs
	sans := extractExtension(fullStr, "Subject Alternative Name:")

	// Key Usage
	keyUsage := extractExtension(fullStr, "Key Usage:")

	// Extended Key Usage
	extKeyUsage := extractExtension(fullStr, "Extended Key Usage:")

	// Basic Constraints
	basicConst := extractExtension(fullStr, "Basic Constraints:")

	// Full view fields
	version := extractVersion(fullStr)
	authorityKeyID := extractExtension(fullStr, "Authority Key Identifier:")
	subjectKeyID := extractExtension(fullStr, "Subject Key Identifier:")

	// Authority Information Access
	aiaCAIssuers := ""
	aiaOCSP := ""
	aiaBlock := extractMultiLineExtension(fullStr, "Authority Information Access:")
	if aiaBlock != "" {
		for _, line := range strings.Split(aiaBlock, "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "CA Issuers") {
				if idx := strings.Index(line, "URI:"); idx >= 0 {
					aiaCAIssuers = strings.TrimSpace(line[idx+4:])
				}
			}
			if strings.Contains(line, "OCSP") {
				if idx := strings.Index(line, "URI:"); idx >= 0 {
					aiaOCSP = strings.TrimSpace(line[idx+4:])
				}
			}
		}
	}

	// CRL Distribution Points
	crlDist := ""
	crlBlock := extractMultiLineExtension(fullStr, "CRL Distribution Points:")
	if crlBlock != "" {
		for _, line := range strings.Split(crlBlock, "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "URI:") {
				if idx := strings.Index(line, "URI:"); idx >= 0 {
					crlDist = strings.TrimSpace(line[idx+4:])
					break
				}
			}
		}
	}

	// Certificate Policies
	certPoliciesOID := ""
	certPoliciesCPS := ""
	policyBlock := extractMultiLineExtension(fullStr, "Certificate Policies:")
	if policyBlock != "" {
		for _, line := range strings.Split(policyBlock, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Policy:") {
				certPoliciesOID = strings.TrimSpace(strings.TrimPrefix(line, "Policy:"))
			}
			if strings.Contains(line, "CPS:") {
				if idx := strings.Index(line, "CPS:"); idx >= 0 {
					certPoliciesCPS = strings.TrimSpace(line[idx+4:])
				}
			}
		}
	}

	// Signature Value (first 64 chars)
	sigValue := extractSignatureValue(fullStr)

	certType := fmt.Sprintf("Certificate %d of %d", num, total)
	if subject == issuer {
		certType += " — Root CA (self-signed)"
	} else if num == 1 {
		certType += " — End-entity certificate"
	} else {
		certType += " — Intermediate CA"
	}

	valid := "Valid"
	validColor := "green"
	if exec.Command("openssl", "x509", "-in", certFile, "-noout", "-checkend", "0").Run() != nil {
		valid = "Expired"
		validColor = "red"
	} else if exec.Command("openssl", "x509", "-in", certFile, "-noout", "-checkend", "2592000").Run() != nil {
		valid = "Expires in less than 30 days"
		validColor = "yellow"
	}

	return &CertInfo{
		CN: cn, Subject: subject, Issuer: issuer,
		NotBefore: notBefore, NotAfter: notAfter,
		Serial: serial, Fingerprint: fp,
		SigAlg: sigAlg, KeyType: keyType, KeySize: keySize,
		SANs: sans, KeyUsage: keyUsage, ExtKeyUsage: extKeyUsage,
		BasicConstraints: basicConst,
		CertType: certType, Valid: valid, ValidColor: validColor,
		Version:         version,
		AuthorityKeyID:  authorityKeyID,
		SubjectKeyID:    subjectKeyID,
		AIACAIssuers:    aiaCAIssuers,
		AIAOCSP:         aiaOCSP,
		CRLDistPoints:   crlDist,
		CertPoliciesOID: certPoliciesOID,
		CertPoliciesCPS: certPoliciesCPS,
		SignatureValue:  sigValue,
	}
}

// Extracts the value of a simple field from the openssl text (first occurrence)
func extractField(text, label string) string {
	idx := strings.Index(text, label)
	if idx == -1 {
		return ""
	}
	rest := text[idx+len(label):]
	nl := strings.Index(rest, "\n")
	if nl == -1 {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(rest[:nl])
}

// Extracts the value of an X509v3 extension (label on one line, value on same or next line)
func extractExtension(text, label string) string {
	idx := strings.Index(text, label)
	if idx == -1 {
		return ""
	}
	rest := text[idx+len(label):]
	// The value may be on the same line or the next
	nl := strings.Index(rest, "\n")
	if nl == -1 {
		return strings.TrimSpace(rest)
	}
	sameLine := strings.TrimSpace(rest[:nl])
	if sameLine != "" {
		return sameLine
	}
	// Value on the next line (indented)
	rest = rest[nl+1:]
	nl = strings.Index(rest, "\n")
	if nl == -1 {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(rest[:nl])
}

// Extracts a multi-line extension block (e.g., AIA, CRL, Policies)
func extractMultiLineExtension(text, label string) string {
	idx := strings.Index(text, label)
	if idx == -1 {
		return ""
	}
	rest := text[idx+len(label):]
	nl := strings.Index(rest, "\n")
	if nl == -1 {
		return strings.TrimSpace(rest)
	}
	// Skip the label line
	rest = rest[nl+1:]

	var lines []string
	for {
		nl = strings.Index(rest, "\n")
		if nl == -1 {
			line := strings.TrimSpace(rest)
			if line != "" {
				lines = append(lines, line)
			}
			break
		}
		line := rest[:nl]
		// Extension blocks are indented; stop when we hit a non-indented line
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			break
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			break
		}
		lines = append(lines, trimmed)
		rest = rest[nl+1:]
	}
	return strings.Join(lines, "\n")
}

// Extracts the certificate version (e.g., "V3")
func extractVersion(text string) string {
	v := extractField(text, "Version:")
	if v == "" {
		return ""
	}
	// Typically "3 (0x2)" — we show "V3"
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "3") {
		return "V3"
	}
	if strings.HasPrefix(v, "1") {
		return "V1"
	}
	return "V" + strings.Split(v, " ")[0]
}

// Extracts the signature value (first 64 hex chars)
func extractSignatureValue(text string) string {
	marker := "Signature Value:"
	idx := strings.Index(text, marker)
	if idx == -1 {
		return ""
	}
	rest := text[idx+len(marker):]

	// Collect hex bytes from subsequent indented lines
	var hexParts []string
	for {
		nl := strings.Index(rest, "\n")
		if nl == -1 {
			break
		}
		rest = rest[nl+1:]
		line := strings.TrimSpace(rest[:strings.Index(rest+"\n", "\n")])
		if line == "" || (len(line) > 0 && line[0] != ' ' && !isHexLine(line)) {
			// If first char is not a hex digit or colon, we're done
			if !isHexLine(line) {
				break
			}
		}
		hexParts = append(hexParts, strings.ReplaceAll(line, ":", ""))
		if len(strings.Join(hexParts, "")) >= 64 {
			break
		}
	}
	result := strings.Join(hexParts, "")
	result = strings.ReplaceAll(result, " ", "")
	if len(result) > 64 {
		result = result[:64]
	}
	if result != "" {
		result += "..."
	}
	return result
}

func isHexLine(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':' || c == ' ') {
			return false
		}
	}
	return true
}

func extractCN(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") || strings.HasPrefix(part, "CN =") {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(part, "CN="), "CN ="))
		}
	}
	return subject
}

func runCmd(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}
