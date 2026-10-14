package ossl

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRunPassesPasswordViaEnv(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not in PATH")
	}
	dir := t.TempDir()
	enc := filepath.Join(dir, "enc.key")
	if err := Run("", "s3cret", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
		"-aes256", "-pass", PassOut, "-out", enc); err != nil {
		t.Fatalf("genpkey: %v", err)
	}
	if err := Run("s3cret", "", "pkey", "-in", enc, "-passin", PassIn, "-noout"); err != nil {
		t.Errorf("right password rejected: %v", err)
	}
	if err := Run("wrong", "", "pkey", "-in", enc, "-passin", PassIn, "-noout"); err == nil {
		t.Error("wrong password accepted")
	}
}

func TestTempFileIsPrivateAndRemoved(t *testing.T) {
	p1, c1, err := TempFile("certui_test_*.pem")
	if err != nil {
		t.Fatal(err)
	}
	p2, c2, _ := TempFile("certui_test_*.pem")
	defer c2()
	if p1 == p2 {
		t.Errorf("temp files collide: %s", p1)
	}
	st, err := os.Stat(p1)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, err = %v; want 0600", st.Mode().Perm(), err)
	}
	c1()
	if _, err := os.Stat(p1); !os.IsNotExist(err) {
		t.Errorf("cleanup did not remove %s", p1)
	}
}
