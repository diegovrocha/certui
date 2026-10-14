// Package ossl centralises how certui invokes the openssl binary: passwords
// travel through environment variables (-passin env:… / -passout env:…) so
// they never appear on the process command line, and temporary files are
// unique, private (0600) and removed by the caller.
package ossl

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	passInEnv  = "CERTUI_PASSIN"
	passOutEnv = "CERTUI_PASSOUT"

	// PassIn / PassOut are the openssl password arguments that read the
	// values given to Run.
	PassIn  = "env:" + passInEnv
	PassOut = "env:" + passOutEnv
)

// Run executes openssl with args. passin/passout are exposed only through
// the child's environment and referenced in args via PassIn / PassOut.
// On failure the first line of openssl's output is folded into the error.
func Run(passin, passout string, args ...string) error {
	cmd := exec.Command("openssl", args...)
	cmd.Env = append(os.Environ(), passInEnv+"="+passin, passOutEnv+"="+passout)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = msg[:i]
		}
		if msg != "" {
			return fmt.Errorf("%v: %s", err, msg)
		}
		return err
	}
	return nil
}

// TempFile creates an empty, uniquely named 0600 file and returns its path
// with a cleanup func that removes it. Callers should `defer cleanup()`.
func TempFile(pattern string) (string, func(), error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", func() {}, err
	}
	f.Close()
	path := f.Name()
	return path, func() { os.Remove(path) }, nil
}

// DetectLegacy returns []string{"-legacy"} when the installed OpenSSL exposes
// the legacy provider (needed for RC2/3DES PKCS#12 files), nil otherwise.
func DetectLegacy() []string {
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
