package extract

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/diegovrocha/certui/internal/history"
	"github.com/diegovrocha/certui/internal/ossl"
	"github.com/diegovrocha/certui/internal/ui"
)

type step int

const (
	stepFile step = iota
	stepKind
	stepPassword
	stepOutput
	stepRunning
	stepDone
)

// KeyKind selects which half of the key pair to extract.
type KeyKind int

const (
	KindPublic KeyKind = iota
	KindPrivate
)

var kindLabels = []string{
	"Public key   (from certificate, PFX/P12 or private key)",
	"Private key  (from PFX/P12 or PEM bundle with key)",
}

type Model struct {
	step     step
	picker   ui.FilePicker
	input    textinput.Model
	kind     KeyKind
	optCur   int
	infile   string
	password string
	outfile  string
	result   string
	success  bool
	showHelp bool
}

func New() tea.Model {
	return Model{
		step:   stepFile,
		picker: ui.NewAllFilePicker("Select the certificate / PFX / key file"),
	}
}

func (m Model) Init() tea.Cmd { return textinput.Blink }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case extractResult:
		m.success = msg.success
		m.result = msg.message
		m.step = stepDone
		if msg.success {
			history.Log("extract",
				history.KV("kind", kindName(m.kind)),
				history.KV("input", m.infile),
				history.KV("output", m.outfile))
		}
		return m, nil
	case tea.KeyMsg:
		// Help overlay: only on non-input steps
		if m.step == stepKind || m.step == stepDone || m.step == stepRunning {
			if msg.String() == "?" {
				m.showHelp = !m.showHelp
				return m, nil
			}
			if m.showHelp {
				if msg.String() == "esc" {
					m.showHelp = false
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
			m.step = stepKind
			m.optCur = 0
			return m, nil
		}
		return m, cmd

	case stepKind:
		if k, ok := msg.(tea.KeyMsg); ok {
			switch k.String() {
			case "up", "k":
				if m.optCur > 0 {
					m.optCur--
				}
			case "down", "j":
				if m.optCur < len(kindLabels)-1 {
					m.optCur++
				}
			case "enter":
				m.kind = KeyKind(m.optCur)
				if needsPassword(m.infile, m.kind) {
					m.step = stepPassword
					m.input = textinput.New()
					m.input.Placeholder = "Password (leave empty if none)"
					m.input.EchoMode = textinput.EchoPassword
					return m, m.input.Focus()
				}
				return m.toOutput()
			}
		}
		return m, nil

	case stepPassword:
		if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" {
			m.password = m.input.Value()
			return m.toOutput()
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd

	case stepOutput:
		if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" {
			m.outfile = m.input.Value()
			m.step = stepRunning
			return m, m.runExtract()
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m Model) toOutput() (tea.Model, tea.Cmd) {
	m.step = stepOutput
	m.input = textinput.New()
	m.input.SetValue(DefaultOutput(m.infile, m.kind))
	return m, m.input.Focus()
}

// DefaultOutput suggests an output filename next to the input file.
func DefaultOutput(infile string, kind KeyKind) string {
	base := strings.TrimSuffix(filepath.Base(infile), filepath.Ext(infile))
	if kind == KindPrivate {
		return base + "_private.key"
	}
	return base + "_public.pem"
}

type extractResult struct {
	success bool
	message string
}

func (m Model) runExtract() tea.Cmd {
	return func() tea.Msg {
		if err := Extract(m.infile, m.kind, m.password, m.outfile); err != nil {
			return extractResult{false, err.Error()}
		}
		lines := "File: " + m.outfile
		if m.kind == KindPrivate {
			lines += "\nFormat: PEM (unencrypted)  Permission: 600"
		} else {
			lines += "\nFormat: PEM (SubjectPublicKeyInfo)"
		}
		return extractResult{true, lines}
	}
}

// ---------------------------------------------------------------------------
// Extraction logic
// ---------------------------------------------------------------------------

type format int

const (
	fmtPKCS12 format = iota
	fmtPEM
	fmtDER
)

func detectFormat(file string) format {
	switch strings.ToLower(filepath.Ext(file)) {
	case ".pfx", ".p12":
		return fmtPKCS12
	}
	data, err := os.ReadFile(file)
	if err == nil && strings.Contains(string(data), "-----BEGIN ") {
		return fmtPEM
	}
	return fmtDER
}

func pemContains(file string, markers ...string) bool {
	data, err := os.ReadFile(file)
	if err != nil {
		return false
	}
	s := string(data)
	for _, mk := range markers {
		if strings.Contains(s, mk) {
			return true
		}
	}
	return false
}

func hasCertificate(file string) bool {
	return pemContains(file, "-----BEGIN CERTIFICATE-----", "-----BEGIN TRUSTED CERTIFICATE-----")
}

func hasPrivateKey(file string) bool {
	return pemContains(file, "PRIVATE KEY-----")
}

func isEncryptedKey(file string) bool {
	return pemContains(file, "-----BEGIN ENCRYPTED PRIVATE KEY-----", "Proc-Type: 4,ENCRYPTED")
}

// needsPassword reports whether extracting kind from file requires a password
// prompt. PFX/P12 always do; PEM files only when the key we read is encrypted.
func needsPassword(file string, kind KeyKind) bool {
	switch detectFormat(file) {
	case fmtPKCS12:
		return true
	case fmtPEM:
		if kind == KindPublic && hasCertificate(file) {
			return false
		}
		return isEncryptedKey(file)
	}
	return false
}

// Extract writes the public or private key contained in infile to outfile
// as PEM. Supported inputs: PFX/P12, PEM (certificate, key or bundle) and
// DER (certificate or key). Private keys are written unencrypted with mode 600.
func Extract(infile string, kind KeyKind, password, outfile string) error {
	if outfile == "" {
		return errors.New("output file is required")
	}
	inStat, err := os.Stat(infile)
	if err != nil {
		return fmt.Errorf("cannot read input: %w", err)
	}
	if outStat, err := os.Stat(outfile); err == nil && os.SameFile(inStat, outStat) {
		return errors.New("output file must be different from the input file")
	}

	switch detectFormat(infile) {
	case fmtPKCS12:
		err = extractFromPKCS12(infile, kind, password, outfile)
	case fmtPEM:
		err = extractFromPEM(infile, kind, password, outfile)
	default:
		err = extractFromDER(infile, kind, password, outfile)
	}
	if err != nil {
		return err
	}
	if kind == KindPrivate {
		return os.Chmod(outfile, 0o600)
	}
	return nil
}

func extractFromPKCS12(infile string, kind KeyKind, password, outfile string) error {
	legacy := ossl.DetectLegacy()
	tmp, cleanup, err := ossl.TempFile("certui_extract_*.pem")
	if err != nil {
		return err
	}
	defer cleanup()

	if kind == KindPrivate {
		args := append([]string{"pkcs12", "-in", infile, "-out", tmp,
			"-passin", ossl.PassIn, "-nocerts", "-nodes"}, legacy...)
		if err := ossl.Run(password, "", args...); err != nil {
			return fmt.Errorf("could not open PFX/P12 (wrong password?): %w", err)
		}
		if !hasPrivateKey(tmp) {
			return errors.New("the PFX/P12 does not contain a private key")
		}
		// Re-encode through pkey to drop the "Bag Attributes" header lines.
		return ossl.Run("", "", "pkey", "-in", tmp, "-out", outfile)
	}

	args := append([]string{"pkcs12", "-in", infile, "-out", tmp,
		"-passin", ossl.PassIn, "-nokeys", "-clcerts"}, legacy...)
	if err := ossl.Run(password, "", args...); err != nil {
		return fmt.Errorf("could not open PFX/P12 (wrong password?): %w", err)
	}
	if hasCertificate(tmp) {
		return ossl.Run("", "", "x509", "-in", tmp, "-pubkey", "-noout", "-out", outfile)
	}
	// No leaf certificate in the bundle: derive the public key from the private key.
	args = append([]string{"pkcs12", "-in", infile, "-out", tmp,
		"-passin", ossl.PassIn, "-nocerts", "-nodes"}, legacy...)
	if err := ossl.Run(password, "", args...); err != nil {
		return fmt.Errorf("could not open PFX/P12: %w", err)
	}
	if !hasPrivateKey(tmp) {
		return errors.New("the PFX/P12 contains neither a certificate nor a private key")
	}
	return ossl.Run("", "", "pkey", "-in", tmp, "-pubout", "-out", outfile)
}

func extractFromPEM(infile string, kind KeyKind, password, outfile string) error {
	if kind == KindPrivate {
		if !hasPrivateKey(infile) {
			return errors.New("this file has no private key — a certificate (.cer/.crt/.pem) " +
				"only carries the public key. Use the PFX/P12 or the original .key file")
		}
		return keyErr(ossl.Run(password, "", "pkey", "-in", infile, "-passin", ossl.PassIn, "-out", outfile))
	}

	if hasCertificate(infile) {
		return extractLeafPublic(infile, outfile)
	}
	if hasPrivateKey(infile) {
		return keyErr(ossl.Run(password, "", "pkey", "-in", infile, "-passin", ossl.PassIn, "-pubout", "-out", outfile))
	}
	if pemContains(infile, "-----BEGIN PUBLIC KEY-----", "-----BEGIN RSA PUBLIC KEY-----") {
		return ossl.Run("", "", "pkey", "-pubin", "-in", infile, "-pubout", "-out", outfile)
	}
	return errors.New("no certificate or key found in this PEM file")
}

// keyErr explains the usual cause of a failure to read a PEM private key.
func keyErr(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("could not read the private key (wrong password?): %w", err)
}

// extractLeafPublic writes the public key of the end-entity certificate in a
// PEM bundle, whatever the order of the chain (leaf→CA or CA→leaf).
func extractLeafPublic(infile, outfile string) error {
	leaf, err := leafCertPEM(infile)
	if err != nil {
		return err
	}
	tmp, cleanup, err := ossl.TempFile("certui_extract_leaf_*.pem")
	if err != nil {
		return err
	}
	defer cleanup()
	if err := os.WriteFile(tmp, leaf, 0o600); err != nil {
		return err
	}
	return ossl.Run("", "", "x509", "-in", tmp, "-pubkey", "-noout", "-out", outfile)
}

// leafCertPEM returns the PEM of the end-entity certificate in file: the one
// that issued no other certificate in the bundle, preferring a non-CA.
func leafCertPEM(file string) ([]byte, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var blocks []*pem.Block
	var certs []*x509.Certificate
	for rest := data; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			continue
		}
		blocks = append(blocks, b)
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no valid certificate found in this PEM file")
	}

	issuesOther := func(i int) bool {
		for j, c := range certs {
			if j != i && bytes.Equal(c.RawIssuer, certs[i].RawSubject) &&
				!bytes.Equal(c.RawSubject, c.RawIssuer) {
				return true
			}
		}
		return false
	}
	best := -1
	for i, c := range certs {
		if issuesOther(i) {
			continue
		}
		if !c.IsCA {
			best = i
			break
		}
		if best == -1 {
			best = i
		}
	}
	if best == -1 {
		best = 0
	}
	return pem.EncodeToMemory(blocks[best]), nil
}

func extractFromDER(infile string, kind KeyKind, password, outfile string) error {
	if kind == KindPrivate {
		if err := ossl.Run(password, "", "pkey", "-inform", "DER", "-in", infile,
			"-passin", ossl.PassIn, "-out", outfile); err != nil {
			return errors.New("this file has no private key — a DER certificate only " +
				"carries the public key. Use the PFX/P12 or the original .key file")
		}
		return nil
	}

	if err := ossl.Run("", "", "x509", "-inform", "DER", "-in", infile, "-pubkey", "-noout", "-out", outfile); err == nil {
		return nil
	}
	if err := ossl.Run(password, "", "pkey", "-inform", "DER", "-in", infile,
		"-passin", ossl.PassIn, "-pubout", "-out", outfile); err != nil {
		return errors.New("could not read file as a certificate or key (PEM, DER or PFX/P12)")
	}
	return nil
}

func kindName(k KeyKind) string {
	if k == KindPrivate {
		return "private"
	}
	return "public"
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

const title = "Extract key (public / private)"

func (m Model) View() string {
	if m.showHelp {
		return m.renderHelp()
	}
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(ui.Banner())
	b.WriteString("\n  " + ui.TitleStyle.Render("── "+title+" ──") + "\n\n")

	switch m.step {
	case stepFile:
		b.WriteString(m.picker.View())

	case stepKind:
		b.WriteString(fmt.Sprintf("  File: %s\n\n", ui.ActiveStyle.Render(m.infile)))
		b.WriteString("  Which key do you want to extract?\n\n")
		for i, o := range kindLabels {
			cursor := "  "
			style := ui.InactiveStyle
			if i == m.optCur {
				cursor = ui.ActiveStyle.Render("➤ ")
				style = ui.ActiveStyle
			}
			b.WriteString(fmt.Sprintf("  %s%s\n", cursor, style.Render(o)))
		}

	case stepPassword:
		b.WriteString(fmt.Sprintf("  File: %s\n\n", ui.ActiveStyle.Render(m.infile)))
		b.WriteString("  🔑 Password\n\n")
		b.WriteString("  " + m.input.View() + "\n")

	case stepOutput:
		b.WriteString("  Output file:\n\n")
		b.WriteString("  " + m.input.View() + "\n")

	case stepRunning:
		b.WriteString("  ⏳ Processing...\n")

	case stepDone:
		if m.success {
			b.WriteString(ui.ResultBox(true, "Success!", strings.Split(m.result, "\n")...))
		} else {
			b.WriteString(ui.ResultBox(false, "Error", m.result))
		}
	}

	b.WriteString("\n  " + ui.DimStyle.Render("? help  esc back  ↑/↓ choose  enter confirm  ctrl+c quit") + "\n")
	return b.String()
}

func (m Model) renderHelp() string {
	sections := []ui.HelpSection{
		{
			Title: "Inputs",
			Entries: []ui.HelpEntry{
				{Key: "PFX/P12", Desc: "Public or private key (asks for password)"},
				{Key: "CER/CRT/PEM", Desc: "Public key of the end-entity certificate"},
				{Key: "KEY/PEM", Desc: "Private key (decrypted) or its public key"},
			},
		},
		{
			Title: "Steps",
			Entries: []ui.HelpEntry{
				{Key: "↑/↓", Desc: "Choose public or private key"},
				{Key: "enter", Desc: "Confirm current step"},
			},
		},
		ui.CommonHelp(),
	}
	return "\n" + ui.Banner() + "  " + ui.TitleStyle.Render("── "+title+" ──") + "\n" + ui.RenderHelp("Extract key — Help", sections)
}

// CapturesEsc tells the menu to forward esc to this screen instead of
// returning to the main menu (help overlay or a nested view is open).
func (m Model) CapturesEsc() bool { return m.showHelp }
