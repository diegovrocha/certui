package extract

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func ensureOpenSSL(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not in PATH")
	}
}

type fixture struct {
	dir, key, cert, der, p12, encKey string
	pub                              string // expected public key PEM
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ensureOpenSSL(t)
	dir := t.TempDir()
	f := fixture{
		dir:    dir,
		key:    filepath.Join(dir, "site.key"),
		cert:   filepath.Join(dir, "site.crt"),
		der:    filepath.Join(dir, "site.cer"),
		p12:    filepath.Join(dir, "site.p12"),
		encKey: filepath.Join(dir, "enc.key"),
	}
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("openssl", args...).CombinedOutput(); err != nil {
			t.Fatalf("openssl %v: %v\n%s", args, err, out)
		}
	}
	run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f.key, "-out", f.cert,
		"-days", "1", "-subj", "/CN=site")
	run("x509", "-in", f.cert, "-outform", "DER", "-out", f.der)
	run("pkcs12", "-export", "-in", f.cert, "-inkey", f.key, "-out", f.p12, "-passout", "pass:secret")
	run("pkey", "-in", f.key, "-aes256", "-passout", "pass:keypass", "-out", f.encKey)

	pub, err := exec.Command("openssl", "pkey", "-in", f.key, "-pubout").Output()
	if err != nil {
		t.Fatal(err)
	}
	f.pub = string(pub)
	return f
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestExtractPublic(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name, in, pass string
	}{
		{"pem cert", f.cert, ""},
		{"der cert", f.der, ""},
		{"pfx", f.p12, "secret"},
		{"private key", f.key, ""},
		{"encrypted key", f.encKey, "keypass"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := filepath.Join(f.dir, strings.ReplaceAll(c.name, " ", "_")+"_pub.pem")
			if err := Extract(c.in, KindPublic, c.pass, out); err != nil {
				t.Fatalf("Extract: %v", err)
			}
			if got := readFile(t, out); got != f.pub {
				t.Errorf("public key mismatch:\n%s\nwant:\n%s", got, f.pub)
			}
		})
	}
}

func TestExtractPrivate(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name, in, pass string
	}{
		{"pfx", f.p12, "secret"},
		{"encrypted key", f.encKey, "keypass"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := filepath.Join(f.dir, strings.ReplaceAll(c.name, " ", "_")+".key")
			if err := Extract(c.in, KindPrivate, c.pass, out); err != nil {
				t.Fatalf("Extract: %v", err)
			}
			got := readFile(t, out)
			if !strings.HasPrefix(got, "-----BEGIN PRIVATE KEY-----") {
				t.Errorf("expected unencrypted PEM key without bag attributes, got:\n%s", got)
			}
			pub, err := exec.Command("openssl", "pkey", "-in", out, "-pubout").Output()
			if err != nil || string(pub) != f.pub {
				t.Errorf("extracted key does not match certificate (err=%v)", err)
			}
			st, _ := os.Stat(out)
			if st.Mode().Perm() != 0o600 {
				t.Errorf("perm = %v, want 0600", st.Mode().Perm())
			}
		})
	}
}

func TestExtractErrors(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name, in, pass string
		kind           KeyKind
		wantSub        string
	}{
		{"private from pem cert", f.cert, "", KindPrivate, "no private key"},
		{"private from der cert", f.der, "", KindPrivate, "no private key"},
		{"pfx wrong password", f.p12, "nope", KindPrivate, "wrong password"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Extract(c.in, c.kind, c.pass, filepath.Join(f.dir, "out"))
			if err == nil || !strings.Contains(err.Error(), c.wantSub) {
				t.Errorf("err = %v, want containing %q", err, c.wantSub)
			}
		})
	}
}

func TestNeedsPassword(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		in   string
		kind KeyKind
		want bool
	}{
		{f.p12, KindPublic, true},
		{f.p12, KindPrivate, true},
		{f.cert, KindPublic, false},
		{f.der, KindPublic, false},
		{f.key, KindPrivate, false},
		{f.encKey, KindPrivate, true},
		{f.encKey, KindPublic, true},
	}
	for _, c := range cases {
		if got := needsPassword(c.in, c.kind); got != c.want {
			t.Errorf("needsPassword(%s, %s) = %v, want %v", filepath.Base(c.in), kindName(c.kind), got, c.want)
		}
	}
}

func TestDefaultOutput(t *testing.T) {
	if got := DefaultOutput("/x/site.p12", KindPrivate); got != "site_private.key" {
		t.Errorf("got %q", got)
	}
	if got := DefaultOutput("/x/site.crt", KindPublic); got != "site_public.pem" {
		t.Errorf("got %q", got)
	}
}

func TestUpdateFlowSkipsPasswordForCert(t *testing.T) {
	f := newFixture(t)
	m := New().(Model)
	m.step = stepKind
	m.infile = f.cert

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if m.step != stepOutput {
		t.Fatalf("step = %v, want stepOutput", m.step)
	}
	if m.input.Value() != "site_public.pem" {
		t.Errorf("default output = %q", m.input.Value())
	}
}

func TestUpdateFlowAsksPasswordForPfx(t *testing.T) {
	f := newFixture(t)
	m := New().(Model)
	m.step = stepKind
	m.infile = f.p12

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	next, _ = next.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if m.kind != KindPrivate || m.step != stepPassword {
		t.Fatalf("kind=%v step=%v, want private/stepPassword", m.kind, m.step)
	}
}

func TestExtractRejectsSameInputAndOutput(t *testing.T) {
	f := newFixture(t)
	before := readFile(t, f.cert)
	if err := Extract(f.cert, KindPublic, "", f.cert); err == nil {
		t.Fatal("expected error when output == input")
	}
	if readFile(t, f.cert) != before {
		t.Error("input certificate was modified")
	}
}

// A bundle in CA→leaf order must still yield the leaf's public key.
func TestExtractPublicFromReversedChain(t *testing.T) {
	f := newFixture(t)
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("openssl", args...).CombinedOutput(); err != nil {
			t.Fatalf("openssl %v: %v\n%s", args, err, out)
		}
	}
	caKey, caCrt := filepath.Join(f.dir, "ca.key"), filepath.Join(f.dir, "ca.crt")
	csr, leaf := filepath.Join(f.dir, "leaf.csr"), filepath.Join(f.dir, "leaf.crt")
	run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", caKey, "-out", caCrt,
		"-days", "1", "-subj", "/CN=Test CA")
	run("req", "-new", "-key", f.key, "-out", csr, "-subj", "/CN=leaf")
	run("x509", "-req", "-in", csr, "-CA", caCrt, "-CAkey", caKey, "-CAcreateserial",
		"-out", leaf, "-days", "1")

	for name, order := range map[string][]string{
		"leaf_first": {leaf, caCrt},
		"ca_first":   {caCrt, leaf},
	} {
		bundle := filepath.Join(f.dir, name+".pem")
		var data []byte
		for _, p := range order {
			data = append(data, readFile(t, p)...)
		}
		os.WriteFile(bundle, data, 0o644)
		out := filepath.Join(f.dir, name+"_pub.pem")
		if err := Extract(bundle, KindPublic, "", out); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := readFile(t, out); got != f.pub {
			t.Errorf("%s: got CA key instead of leaf key", name)
		}
	}
}

func TestExtractEncryptedKeyWrongPassword(t *testing.T) {
	f := newFixture(t)
	err := Extract(f.encKey, KindPrivate, "nope", filepath.Join(f.dir, "x.key"))
	if err == nil || !strings.Contains(err.Error(), "wrong password") {
		t.Errorf("err = %v, want hint about wrong password", err)
	}
}
