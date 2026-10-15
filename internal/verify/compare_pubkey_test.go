package verify

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Comparing a bare public key (Extract key → public) with a certificate
// compares the keys instead of failing with "Cannot read certificate".
func TestComparePublicKeyWithCertificate(t *testing.T) {
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
	mk := func(name string) (crt, der, pub string) {
		key := filepath.Join(dir, name+".key")
		crt, der, pub = filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".cer"), filepath.Join(dir, name+"_public.pem")
		run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
			"-days", "1", "-subj", "/CN="+name)
		run("x509", "-in", crt, "-outform", "DER", "-out", der)
		run("pkey", "-in", key, "-pubout", "-out", pub)
		return
	}
	crtA, derA, pubA := mk("a")
	crtB, _, pubB := mk("b")

	compare := func(f1, f2 string) compareResult {
		m := &CompareHashModel{file1: f1, file2: f2, pem1: f1, pem2: f2}
		return m.doCompare()().(compareResult)
	}
	cases := []struct {
		name   string
		f1, f2 string
		match  bool
	}{
		{"pub vs own cert", pubA, crtA, true},
		{"cert vs own pub", crtA, pubA, true},
		{"pub vs own DER cert", pubA, derA, true},
		{"pub vs pub", pubA, pubA, true},
		{"pub vs other cert", pubA, crtB, false},
		{"pub vs other pub", pubA, pubB, false},
	}
	for _, c := range cases {
		res := compare(c.f1, c.f2)
		if res.err != "" {
			t.Errorf("%s: err %q", c.name, res.err)
			continue
		}
		if !res.byKey || res.match != c.match {
			t.Errorf("%s: byKey=%v match=%v, want byKey match=%v", c.name, res.byKey, res.match, c.match)
		}
	}

	// Two certificates still compare by fingerprint.
	if res := compare(crtA, crtA); res.byKey || !res.match {
		t.Errorf("cert vs cert: byKey=%v match=%v", res.byKey, res.match)
	}

	// Multi compare groups a cert with its own public key.
	m := &CompareHashModel{files: []string{pubA, crtA, crtB}, pems: []string{pubA, crtA, crtB}}
	mr := m.doMultiCompare()().(multiCompareResult)
	if mr.err != "" || !mr.matrix[0][1] || mr.matrix[0][2] || len(mr.groups) != 2 {
		t.Errorf("multi: err=%q matrix=%v groups=%v", mr.err, mr.matrix, mr.groups)
	}

	// Unreadable file: short, clear error with the file name only.
	junk := filepath.Join(dir, "junk.pem")
	run("rand", "-out", junk, "64")
	if res := compare(junk, crtA); !strings.Contains(res.err, "junk.pem: not a certificate or public key") ||
		strings.Contains(res.err, dir) {
		t.Errorf("junk: err = %q", res.err)
	}
}
