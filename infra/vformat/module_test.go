package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatRespectsNestedModuleBoundary(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "dependency")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "go.mod"), "module example.invalid/root\n\ngo 1.27\n")
	write(filepath.Join(nested, "go.mod"), "module example.invalid/dependency\n\ngo 1.18\n")
	// A nested module owns its own formatting/language policy. A root check
	// must still reject an unformatted root file while not parsing this file.
	write(filepath.Join(nested, "bad.go"), "not Go source")
	file := filepath.Join(root, "root.go")
	write(file, "package root\nfunc F(){ }\n")
	check := func() ([]byte, error) {
		return exec.Command("go", "run", "./main.go", "-mode", "check", "-pwd", root).CombinedOutput()
	}
	out, err := check()
	if err == nil || !strings.Contains(string(out), file) || strings.Contains(string(out), "bad.go") {
		t.Fatalf("root check did not respect module boundary: %v\n%s", err, out)
	}
	write(file, "package root\n\nfunc F() {}\n")
	if out, err := check(); err != nil {
		t.Fatalf("formatted root rejected: %v\n%s", err, out)
	}
}
