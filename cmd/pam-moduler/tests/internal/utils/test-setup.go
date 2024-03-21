// Package utils contains the internal test utils
package utils

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/msteinert/pam/v2"
)

// TestSetup is an utility type for having a playground for test PAM modules.
type TestSetup struct {
	t       *testing.T
	workDir string
}

type withWorkDir struct{}

//nolint:revive
func WithWorkDir() withWorkDir {
	return withWorkDir{}
}

// NewTestSetup creates a new TestSetup.
func NewTestSetup(t *testing.T, args ...interface{}) *TestSetup {
	t.Helper()

	ts := &TestSetup{t: t}
	for _, arg := range args {
		switch argType := arg.(type) {
		case withWorkDir:
			ts.ensureWorkDir()
		default:
			t.Fatalf("Unknown parameter of type %v", argType)
		}
	}

	return ts
}

// CreateTemporaryDir creates a temporary directory with provided basename.
func (ts *TestSetup) CreateTemporaryDir(basename string) string {
	tmpDir, err := os.MkdirTemp(os.TempDir(), basename)
	if err != nil {
		ts.t.Fatalf("can't create service path %v", err)
	}

	ts.t.Cleanup(func() { os.RemoveAll(tmpDir) })
	return tmpDir
}

func (ts *TestSetup) ensureWorkDir() string {
	if ts.workDir != "" {
		return ts.workDir
	}

	ts.workDir = ts.CreateTemporaryDir("go-pam-*")
	return ts.workDir
}

// WorkDir returns the test setup work directory.
func (ts TestSetup) WorkDir() string {
	return ts.workDir
}

// GenerateModule generates a PAM module for the provided path and name.
func (ts *TestSetup) GenerateModule(testModulePath string, moduleName string) string {
	cmd := exec.Command("go", "generate", "-C", testModulePath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		ts.t.Fatalf("can't build pam module %v: %s", err, out)
	}

	builtFile := filepath.Join(cmd.Dir, testModulePath, moduleName)
	modulePath := filepath.Join(ts.ensureWorkDir(), filepath.Base(builtFile))
	if err = os.Rename(builtFile, modulePath); err != nil {
		ts.t.Fatalf("can't move module: %v", err)
		os.Remove(builtFile)
	}

	return modulePath
}

func (ts TestSetup) currentFile(skip int) string {
	_, currentFile, _, ok := runtime.Caller(skip)
	if !ok {
		ts.t.Fatalf("can't get current binary path")
	}
	return currentFile
}

// GetCurrentFile returns the current file path.
func (ts TestSetup) GetCurrentFile() string {
	// This is a library so we care about the caller location
	return ts.currentFile(2)
}

// GetCurrentFileDir returns the current file directory.
func (ts TestSetup) GetCurrentFileDir() string {
	return filepath.Dir(ts.currentFile(2))
}

// GenerateModuleDefault generates a default module.
func (ts *TestSetup) GenerateModuleDefault(testModulePath string) string {
	return ts.GenerateModule(testModulePath, "pam_go.so")
}

// CreateService creates a service file.
func (ts *TestSetup) CreateService(serviceName string, services []ServiceLine) string {
	if !pam.CheckPamHasStartConfdir() {
		ts.t.Skip("PAM has no support for custom service paths")
		return ""
	}

	serviceName = strings.ToLower(serviceName)
	serviceFile := filepath.Join(ts.ensureWorkDir(), serviceName)
	var contents = []string{}

	for _, s := range services {
		contents = append(contents, strings.TrimRight(strings.Join([]string{
			s.Action.String(), s.Control.String(), s.Module, strings.Join(s.Args, " "),
		}, "\t"), "\t"))
	}

	if err := os.WriteFile(serviceFile,
		[]byte(strings.Join(contents, "\n")), 0600); err != nil {
		ts.t.Fatalf("can't create service file %v: %v", serviceFile, err)
	}

	return serviceFile
}
