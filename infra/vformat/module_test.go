package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatChecksRootSource(t *testing.T) {
	root := t.TempDir()
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "go.mod"), "module example.invalid/root\n\ngo 1.27\n")
	file := filepath.Join(root, "root.go")
	write(file, "package root\nfunc F(){ }\n")
	check := func() ([]byte, error) {
		return exec.Command("go", "run", "./main.go", "-mode", "check", "-pwd", root).CombinedOutput()
	}
	out, err := check()
	if err == nil || !strings.Contains(string(out), file) {
		t.Fatalf("root formatting violation was not detected: %v\n%s", err, out)
	}
	write(file, "package root\n\nfunc F() {}\n")
	if out, err := check(); err != nil {
		t.Fatalf("formatted root rejected: %v\n%s", err, out)
	}
}
