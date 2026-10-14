package inspect

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestExtractCN(t *testing.T) {
	tests := []struct {
		subject  string
		expected string
	}{
		{"C=BR, O=ICP-Brasil, CN=Meu Certificado", "Meu Certificado"},
		{"CN=meusite.com.br", "meusite.com.br"},
		{"DC=ihf, DC=corp, CN=Itau-R0650", "Itau-R0650"},
		{"C=BR, O=Test", "C=BR, O=Test"}, // no CN returns full subject
		{"CN=RV2 SERVICOS, OU=Certificado PJ A1", "RV2 SERVICOS"},
	}

	for _, tt := range tests {
		result := extractCN(tt.subject)
		if result != tt.expected {
			t.Errorf("extractCN(%q) = %q, expected %q", tt.subject, result, tt.expected)
		}
	}
}

func TestSplitPEM(t *testing.T) {
	// Generate a test cert
	dir := t.TempDir()
	certFile := filepath.Join(dir, "test.crt")
	keyFile := filepath.Join(dir, "test.key")

	err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", keyFile, "-out", certFile,
		"-days", "1", "-subj", "/CN=test").Run()
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	// 1 cert
	certs := splitPEM(certFile)
	defer removeAll(certs)
	if len(certs) != 1 {
		t.Errorf("splitPEM with 1 cert should return 1, returned %d", len(certs))
	}

	// 3 certs (simulated chain)
	chainFile := filepath.Join(dir, "chain.pem")
	certData, _ := os.ReadFile(certFile)
	chainData := string(certData) + "\n" + string(certData) + "\n" + string(certData)
	os.WriteFile(chainFile, []byte(chainData), 0644)

	chain := splitPEM(chainFile)
	defer removeAll(chain)
	if len(chain) != 3 {
		t.Errorf("splitPEM with 3 certs should return 3, returned %d", len(chain))
	}
}

func TestExtractInfo(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "test.crt")
	keyFile := filepath.Join(dir, "test.key")

	err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", keyFile, "-out", certFile,
		"-days", "365", "-subj", "/CN=teste.local/O=TestOrg/C=BR").Run()
	if err != nil {
		t.Fatalf("Failed to generate cert: %v", err)
	}

	info := extractInfo(certFile, 1, 1)
	if info == nil {
		t.Fatal("extractInfo returned nil")
	}

	if info.CN != "teste.local" {
		t.Errorf("CN expected 'teste.local', got '%s'", info.CN)
	}

	if !strings.Contains(info.Subject, "teste.local") {
		t.Errorf("Subject should contain 'teste.local': %s", info.Subject)
	}

	// Self-signed = subject == issuer
	if info.Subject != info.Issuer {
		t.Error("Self-signed cert should have subject == issuer")
	}

	if !strings.Contains(info.CertType, "Root CA") {
		t.Errorf("Self-signed cert should be Root CA, got: %s", info.CertType)
	}

	if info.Valid != "Valid" {
		t.Errorf("Cert with 365 days should be valid, got: %s", info.Valid)
	}

	if info.Serial == "" {
		t.Error("Serial should not be empty")
	}

	if info.Fingerprint == "" {
		t.Error("Fingerprint should not be empty")
	}
}

func TestExtractInfoShortLived(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "short.crt")
	keyFile := filepath.Join(dir, "short.key")

	// Cert with 1 day validity (expires soon)
	err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", keyFile, "-out", certFile,
		"-days", "1", "-subj", "/CN=shortlived").Run()
	if err != nil {
		t.Fatalf("Failed to generate cert: %v", err)
	}

	info := extractInfo(certFile, 1, 1)
	if info == nil {
		t.Fatal("extractInfo returned nil")
	}

	// 1-day cert should be marked as "expires in less than 30 days"
	if info.Valid == "" {
		t.Error("Valid should not be empty")
	}
	if info.ValidColor != "yellow" {
		t.Errorf("1-day cert should have yellow color, got: %s", info.ValidColor)
	}
}

func TestExtractInfoInvalidFile(t *testing.T) {
	dir := t.TempDir()
	badFile := filepath.Join(dir, "bad.pem")
	os.WriteFile(badFile, []byte("not a certificate"), 0644)

	info := extractInfo(badFile, 1, 1)
	if info != nil {
		t.Error("extractInfo should return nil for invalid file")
	}
}

func TestHasPEMMarker(t *testing.T) {
	dir := t.TempDir()

	// PEM file
	pemFile := filepath.Join(dir, "test.pem")
	os.WriteFile(pemFile, []byte("-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----\n"), 0644)
	if !hasPEMMarker(pemFile) {
		t.Error("hasPEMMarker should return true for PEM")
	}

	// Binary file
	derFile := filepath.Join(dir, "test.der")
	os.WriteFile(derFile, []byte{0x30, 0x82, 0x01}, 0644)
	if hasPEMMarker(derFile) {
		t.Error("hasPEMMarker should return false for DER")
	}
}

func TestNewWithFile(t *testing.T) {
	// Non-PFX file: should set pendingInspect and advance to stepResult
	m := NewWithFile("/tmp/example.pem")
	mm := m.(*Model)
	if !mm.pendingInspect {
		t.Error("NewWithFile(.pem) should set pendingInspect=true")
	}
	if mm.step != stepResult {
		t.Errorf("NewWithFile(.pem) step: got %v, want stepResult", mm.step)
	}
	if mm.infile != "/tmp/example.pem" {
		t.Errorf("infile: got %q", mm.infile)
	}

	// After Init(), pendingInspect flips back to false (and returns a cmd)
	cmd := mm.Init()
	if cmd == nil {
		t.Error("Init on pending should return a command")
	}
	if mm.pendingInspect {
		t.Error("Init should consume pendingInspect")
	}

	// PFX file: should go to stepPassword, needPass=true
	m2 := NewWithFile("/tmp/example.pfx")
	mm2 := m2.(*Model)
	if !mm2.needPass {
		t.Error("NewWithFile(.pfx) should set needPass=true")
	}
	if mm2.step != stepPassword {
		t.Errorf("NewWithFile(.pfx) step: got %v want stepPassword", mm2.step)
	}
	if mm2.pendingInspect {
		t.Error("NewWithFile(.pfx) should not set pendingInspect")
	}
}

func TestExtractCNAllFormats(t *testing.T) {
	tests := []struct {
		subject  string
		expected string
	}{
		{"CN=just-cn", "just-cn"},
		// Multiple CN= in different RDNs; first match wins
		{"CN=first.com, O=Org", "first.com"},
		// CN value containing "CN=" substring should not be mis-parsed
		// (extractCN splits on commas then strips CN= prefix)
		{"O=Org, CN=has-CN=inside", "has-CN=inside"},
		// Leading space handling
		{" CN =spaced ", "spaced"},
		// No CN at all returns the raw subject
		{"O=Org, C=US", "O=Org, C=US"},
	}
	for _, tt := range tests {
		if got := extractCN(tt.subject); got != tt.expected {
			t.Errorf("extractCN(%q) = %q, want %q", tt.subject, got, tt.expected)
		}
	}
}

func TestInspectSaveModeToggle(t *testing.T) {
	// Set up a model as if inspection succeeded.
	m := &Model{
		step: stepResult,
		certs: []CertInfo{{CN: "test.com"}},
	}
	// Press 's' to enter save mode.
	keyS := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")}
	next, _ := m.Update(keyS)
	mm := next.(*Model)
	if !mm.saving {
		t.Error("pressing 's' should set saving=true")
	}
}

func TestHasPrivateKeyOnly(t *testing.T) {
	dir := t.TempDir()

	// File with key + cert
	bothFile := filepath.Join(dir, "both.pem")
	os.WriteFile(bothFile, []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n"), 0644)
	if hasPrivateKeyOnly(bothFile) {
		t.Error("File with cert+key should not be 'private key only'")
	}

	// File with key only
	keyFile := filepath.Join(dir, "key.pem")
	os.WriteFile(keyFile, []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"), 0644)
	if !hasPrivateKeyOnly(keyFile) {
		t.Error("File with only key should be 'private key only'")
	}
}

func TestExtractExtensionCritical(t *testing.T) {
	text := `        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
`
	if got := extractExtension(text, "Basic Constraints:"); got != "CA:TRUE (critical)" {
		t.Errorf("Basic Constraints = %q", got)
	}
	if got := extractExtension(text, "X509v3 Key Usage:"); got != "Certificate Sign, CRL Sign (critical)" {
		t.Errorf("Key Usage = %q", got)
	}
	if got := extractExtension(text, "Extended Key Usage:"); got != "TLS Web Server Authentication" {
		t.Errorf("Extended Key Usage = %q", got)
	}
}

// An intermediate CA alone (first in its bundle) must not be labelled end-entity.
func TestExtractInfoClassifiesIntermediateByBasicConstraints(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not in PATH")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("openssl", args...).CombinedOutput(); err != nil {
			t.Fatalf("openssl %v: %v\n%s", args, err, out)
		}
	}
	root, rootKey := filepath.Join(dir, "root.crt"), filepath.Join(dir, "root.key")
	inter, interKey, csr := filepath.Join(dir, "int.crt"), filepath.Join(dir, "int.key"), filepath.Join(dir, "int.csr")
	ext := filepath.Join(dir, "ext.cnf")
	os.WriteFile(ext, []byte("basicConstraints=critical,CA:TRUE\n"), 0o644)
	run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", rootKey, "-out", root, "-days", "1", "-subj", "/CN=Root")
	run("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", interKey, "-out", csr, "-subj", "/CN=Intermediate")
	run("x509", "-req", "-in", csr, "-CA", root, "-CAkey", rootKey, "-CAcreateserial", "-out", inter,
		"-days", "1", "-extfile", ext)

	info := extractInfo(inter, 1, 1)
	if info == nil {
		t.Fatal("extractInfo returned nil")
	}
	if !strings.Contains(info.CertType, "Intermediate CA") {
		t.Errorf("CertType = %q, want Intermediate CA", info.CertType)
	}
	if info.BasicConstraints != "CA:TRUE (critical)" {
		t.Errorf("BasicConstraints = %q", info.BasicConstraints)
	}
}
