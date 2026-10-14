package verify

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Regression: two PFX paths of equal length used to share one temp file, so
// the second extraction overwrote the first and Compare reported a match.
func TestExtractPFXtoPEMSameLengthPathsDoNotCollide(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not in PATH")
	}
	dir := t.TempDir()
	mk := func(name string) string {
		key, crt, p12 := filepath.Join(dir, name+".key"), filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".p12")
		for _, args := range [][]string{
			{"req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
				"-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=" + name},
			{"pkcs12", "-export", "-in", crt, "-inkey", key, "-out", p12, "-passout", "pass:secret"},
		} {
			if out, err := exec.Command("openssl", args...).CombinedOutput(); err != nil {
				t.Fatalf("openssl %v: %v\n%s", args, err, out)
			}
		}
		return p12
	}
	a, b := mk("aaaa"), mk("bbbb") // same path length

	pa, errA := extractPFXtoPEM(a, "secret")
	pb, errB := extractPFXtoPEM(b, "secret")
	if errA != "" || errB != "" {
		t.Fatalf("extract: %q %q", errA, errB)
	}
	defer os.Remove(pa)
	defer os.Remove(pb)
	if pa == pb {
		t.Fatalf("both PFX extracted to %s", pa)
	}
	sa, sb := loadSummary(a, pa), loadSummary(b, pb)
	if sa.fingerprint == "" || sa.fingerprint == sb.fingerprint {
		t.Errorf("different certs reported equal: %q vs %q", sa.fingerprint, sb.fingerprint)
	}
	if !isCmpTemp(pa) || isCmpTemp(a) {
		t.Error("isCmpTemp misclassifies paths")
	}
}

func TestCompareCapturesEscInDiffView(t *testing.T) {
	m := &CompareHashModel{step: cmpDiffView}
	if !m.CapturesEsc() {
		t.Error("diff view must keep esc to return to the result")
	}
	m.step = cmpResultStep
	if m.CapturesEsc() {
		t.Error("result screen should let esc go back to the menu")
	}
}
