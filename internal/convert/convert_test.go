package convert

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// ensureOpenSSL skips the test if openssl is not in PATH.
func ensureOpenSSL(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not in PATH")
	}
}

// genP12 creates a self-signed cert + key and packages them into a .p12 file
// in dir using the given password. Returns the path to the .p12 file.
func genP12(t *testing.T, dir, name, password string) string {
	t.Helper()

	keyFile := filepath.Join(dir, name+".key")
	certFile := filepath.Join(dir, name+".crt")
	p12File := filepath.Join(dir, name+".p12")

	if err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", keyFile, "-out", certFile,
		"-days", "1", "-subj", "/CN="+name).Run(); err != nil {
		t.Fatalf("openssl req failed: %v", err)
	}

	if err := exec.Command("openssl", "pkcs12", "-export",
		"-in", certFile, "-inkey", keyFile,
		"-out", p12File,
		"-passout", "pass:"+password).Run(); err != nil {
		t.Fatalf("openssl pkcs12 -export failed: %v", err)
	}

	return p12File
}

// ---------------------------------------------------------------------------
// convTypeName — pure unit tests
// ---------------------------------------------------------------------------

func TestConvTypeName(t *testing.T) {
	cases := []struct {
		ct   convType
		want string
	}{
		{typePfxPem, "pfx_to_pem"},
		{typePfxCerPem, "pfx_to_cer_pem"},
		{typePfxCerDer, "pfx_to_cer_der"},
		{typePfxKey, "pfx_to_key"},
		{typePfxRepack, "pfx_repack"},
		{typePfxRepackJava, "pfx_repack_java"},
		{convType(999), "unknown"},
	}
	for _, c := range cases {
		if got := convTypeName(c.ct); got != c.want {
			t.Errorf("convTypeName(%d) = %q, want %q", c.ct, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// detectLegacy — smoke test (just verify it returns nil or []string{"-legacy"})
// ---------------------------------------------------------------------------

func TestDetectLegacy(t *testing.T) {
	ensureOpenSSL(t)
	result := detectLegacy()
	if result == nil {
		return // fine — no legacy provider
	}
	if len(result) != 1 || result[0] != "-legacy" {
		t.Errorf("detectLegacy returned unexpected value: %v", result)
	}
}

// ---------------------------------------------------------------------------
// Constructor tests — verify title and convType fields
// ---------------------------------------------------------------------------

func TestNewConstructors(t *testing.T) {
	cases := []struct {
		name     string
		factory  func() Model
		convType convType
		title    string
	}{
		{
			"NewPfxToPem",
			func() Model { return NewPfxToPem().(Model) },
			typePfxPem,
			"PFX/P12 → PEM (certificate + key)",
		},
		{
			"NewPfxToCerPem",
			func() Model { return NewPfxToCerPem().(Model) },
			typePfxCerPem,
			"PFX/P12 → CER (PEM/text)",
		},
		{
			"NewPfxToCerDer",
			func() Model { return NewPfxToCerDer().(Model) },
			typePfxCerDer,
			"PFX/P12 → CER (DER/binary)",
		},
		{
			"NewPfxToKey",
			func() Model { return NewPfxToKey().(Model) },
			typePfxKey,
			"PFX/P12 → Private Key",
		},
		{
			"NewPfxRepack",
			func() Model { return NewPfxRepack().(Model) },
			typePfxRepack,
			"PFX/P12 → P12 (--legacy → modern)",
		},
		{
			"NewPfxRepackJava",
			func() Model { return NewPfxRepackJava().(Model) },
			typePfxRepackJava,
			"PFX/P12 → P12 (modern → Java8/legacy)",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := c.factory()
			if m.convType != c.convType {
				t.Errorf("convType: got %d, want %d", m.convType, c.convType)
			}
			if m.title != c.title {
				t.Errorf("title: got %q, want %q", m.title, c.title)
			}
			if m.step != stepFile {
				t.Errorf("initial step: got %d, want stepFile (%d)", m.step, stepFile)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// runOpenSSL — end-to-end conversion tests using a real P12
// ---------------------------------------------------------------------------

func TestRunOpenSSLPfxToPem(t *testing.T) {
	ensureOpenSSL(t)
	dir := t.TempDir()
	p12 := genP12(t, dir, "test", "secret")

	outFile := filepath.Join(dir, "out.pem")
	legacy := detectLegacy()
	args := append([]string{"pkcs12", "-in", p12, "-out", outFile,
		"-passin", "pass:secret", "-nodes"}, legacy...)
	if err := runOpenSSL(args...); err != nil {
		t.Fatalf("runOpenSSL (pfx→pem) failed: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("output file not readable: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("output PEM file is empty")
	}

	// Verify openssl can parse it back
	if err := exec.Command("openssl", "x509", "-in", outFile, "-noout").Run(); err != nil {
		t.Errorf("output PEM not valid (openssl x509 -noout): %v", err)
	}
}

func TestRunOpenSSLPfxToCerPem(t *testing.T) {
	ensureOpenSSL(t)
	dir := t.TempDir()
	p12 := genP12(t, dir, "test", "secret")

	outFile := filepath.Join(dir, "out.cer")
	legacy := detectLegacy()
	args := append([]string{"pkcs12", "-in", p12, "-out", outFile,
		"-passin", "pass:secret", "-nokeys", "-clcerts"}, legacy...)
	if err := runOpenSSL(args...); err != nil {
		t.Fatalf("runOpenSSL (pfx→cer pem) failed: %v", err)
	}

	if err := exec.Command("openssl", "x509", "-in", outFile, "-noout").Run(); err != nil {
		t.Errorf("output CER (PEM) not valid: %v", err)
	}
}

func TestRunOpenSSLPfxToCerDer(t *testing.T) {
	ensureOpenSSL(t)
	dir := t.TempDir()
	p12 := genP12(t, dir, "test", "secret")

	tmpPem := filepath.Join(dir, "tmp.pem")
	outFile := filepath.Join(dir, "out.cer")

	legacy := detectLegacy()
	args := append([]string{"pkcs12", "-in", p12, "-out", tmpPem,
		"-passin", "pass:secret", "-nokeys", "-clcerts"}, legacy...)
	if err := runOpenSSL(args...); err != nil {
		t.Fatalf("runOpenSSL extract pem step failed: %v", err)
	}
	if err := runOpenSSL("x509", "-in", tmpPem, "-out", outFile, "-outform", "DER"); err != nil {
		t.Fatalf("runOpenSSL DER conversion failed: %v", err)
	}

	// DER file must be parseable
	if err := exec.Command("openssl", "x509", "-in", outFile, "-inform", "DER", "-noout").Run(); err != nil {
		t.Errorf("output CER (DER) not valid: %v", err)
	}
}

func TestRunOpenSSLPfxToKey(t *testing.T) {
	ensureOpenSSL(t)
	dir := t.TempDir()
	p12 := genP12(t, dir, "test", "secret")

	outFile := filepath.Join(dir, "out.key")
	legacy := detectLegacy()
	args := append([]string{"pkcs12", "-in", p12, "-out", outFile,
		"-passin", "pass:secret", "-nocerts", "-nodes"}, legacy...)
	if err := runOpenSSL(args...); err != nil {
		t.Fatalf("runOpenSSL (pfx→key) failed: %v", err)
	}

	if err := exec.Command("openssl", "rsa", "-in", outFile, "-check", "-noout").Run(); err != nil {
		t.Errorf("output key not valid (openssl rsa -check): %v", err)
	}
}

func TestRunOpenSSLPfxRepack(t *testing.T) {
	ensureOpenSSL(t)
	dir := t.TempDir()
	p12 := genP12(t, dir, "test", "secret")

	tmpPem := filepath.Join(dir, "repack_tmp.pem")
	outFile := filepath.Join(dir, "out_new.p12")

	legacy := detectLegacy()
	args := append([]string{"pkcs12", "-in", p12, "-out", tmpPem,
		"-passin", "pass:secret", "-nodes"}, legacy...)
	if err := runOpenSSL(args...); err != nil {
		t.Fatalf("runOpenSSL extract step (repack) failed: %v", err)
	}
	if err := runOpenSSL("pkcs12", "-export", "-in", tmpPem, "-out", outFile,
		"-passout", "pass:newpass"); err != nil {
		t.Fatalf("runOpenSSL repack export failed: %v", err)
	}

	// Verify the new P12 can be listed by openssl
	if err := exec.Command("openssl", "pkcs12", "-in", outFile,
		"-passin", "pass:newpass", "-noout").Run(); err != nil {
		t.Errorf("repacked P12 not valid: %v", err)
	}
}

func TestRunOpenSSLPfxRepackJava(t *testing.T) {
	ensureOpenSSL(t)
	dir := t.TempDir()
	p12 := genP12(t, dir, "test", "secret")

	tmpPem := filepath.Join(dir, "repack_java_tmp.pem")
	outFile := filepath.Join(dir, "out_java.p12")

	legacy := detectLegacy()
	args := append([]string{"pkcs12", "-in", p12, "-out", tmpPem,
		"-passin", "pass:secret", "-nodes"}, legacy...)
	if err := runOpenSSL(args...); err != nil {
		t.Fatalf("runOpenSSL extract step (repack java) failed: %v", err)
	}
	if err := runOpenSSL("pkcs12", "-export", "-in", tmpPem, "-out", outFile,
		"-passout", "pass:javapass",
		"-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1"); err != nil {
		t.Fatalf("runOpenSSL repack (Java8) export failed: %v", err)
	}

	// Verify with -legacy flag if available, otherwise plain
	verifyArgs := []string{"pkcs12", "-in", outFile, "-passin", "pass:javapass", "-noout"}
	if legacy != nil {
		verifyArgs = append(verifyArgs, "-legacy")
	}
	if err := exec.Command("openssl", verifyArgs...).Run(); err != nil {
		t.Errorf("Java8 repacked P12 not valid: %v", err)
	}
}

// ---------------------------------------------------------------------------
// runConversion cmd — integration test via the Model.runConversion() tea.Cmd
// ---------------------------------------------------------------------------

func TestRunConversionRepack(t *testing.T) {
	ensureOpenSSL(t)
	dir := t.TempDir()
	p12 := genP12(t, dir, "src", "srcpass")

	outFile := filepath.Join(dir, "out_repack.p12")

	m := Model{
		convType:  typePfxRepack,
		infile:    p12,
		password:  "srcpass",
		outfile:   outFile,
		password2: "dstpass",
	}

	cmd := m.runConversion()
	msg := cmd()

	result, ok := msg.(convResult)
	if !ok {
		t.Fatalf("expected convResult, got %T", msg)
	}
	if !result.success {
		t.Fatalf("repack conversion failed: %s", result.message)
	}

	if _, err := os.Stat(outFile); err != nil {
		t.Fatalf("output file not created: %v", err)
	}

	if err := exec.Command("openssl", "pkcs12", "-in", outFile,
		"-passin", "pass:dstpass", "-noout").Run(); err != nil {
		t.Errorf("repacked P12 not readable by openssl: %v", err)
	}
}

// ---------------------------------------------------------------------------
// runConvert regressions
// ---------------------------------------------------------------------------

func TestRunConvertKeyForcesMode600OnExistingFile(t *testing.T) {
	ensureOpenSSL(t)
	dir := t.TempDir()
	p12 := genP12(t, dir, "perm", "secret")
	out := filepath.Join(dir, "existing.key")
	if err := os.WriteFile(out, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, ct := range []convType{typePfxKey, typePfxPem} {
		os.Chmod(out, 0o644)
		if _, err := runConvert(ct, p12, "secret", "", out); err != nil {
			t.Fatalf("%s: %v", convTypeName(ct), err)
		}
		if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode = %v, want 0600", convTypeName(ct), st.Mode().Perm())
		}
	}
}

func TestRunConvertRepackLeavesNoTempFiles(t *testing.T) {
	ensureOpenSSL(t)
	dir := t.TempDir()
	t.Setenv("TMPDIR", filepath.Join(dir, "tmp"))
	os.Mkdir(filepath.Join(dir, "tmp"), 0o700)
	p12 := genP12(t, dir, "repack", "secret")

	for _, ct := range []convType{typePfxRepack, typePfxRepackJava, typePfxCerDer} {
		out := filepath.Join(dir, convTypeName(ct)+".out")
		if _, err := runConvert(ct, p12, "secret", "newpass", out); err != nil {
			t.Fatalf("%s: %v", convTypeName(ct), err)
		}
	}
	left, _ := os.ReadDir(filepath.Join(dir, "tmp"))
	if len(left) != 0 {
		t.Errorf("temp files left behind: %v", left)
	}
	// The repacked file opens with the new password only.
	if err := runOpenSSL(append([]string{"pkcs12", "-in", filepath.Join(dir, "pfx_repack.out"),
		"-noout", "-passin", "pass:newpass"}, detectLegacy()...)...); err != nil {
		t.Errorf("repacked p12 rejects new password: %v", err)
	}
}

func TestRunConvertRejectsSameInputAndOutput(t *testing.T) {
	ensureOpenSSL(t)
	dir := t.TempDir()
	p12 := genP12(t, dir, "same", "secret")
	if _, err := runConvert(typePfxRepack, p12, "secret", "x", p12); err == nil {
		t.Error("expected error when output == input")
	}
}
