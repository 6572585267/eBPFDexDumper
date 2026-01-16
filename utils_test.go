package main

import (
	"bytes"
	"compress/gzip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestIsUIDRunningCurrentUID(t *testing.T) {
	uid := uint32(os.Getuid())
	running, err := IsUIDRunning(uid)
	if err != nil {
		t.Fatalf("IsUIDRunning error: %v", err)
	}
	if !running {
		t.Fatalf("expected uid %d to be running", uid)
	}
}

func TestCheckConfigFromReader(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte("CONFIG_DEBUG_INFO_BTF=y\n")); err != nil {
		t.Fatalf("write gz: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gz: %v", err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	if !checkConfigFromReader(reader, "CONFIG_DEBUG_INFO_BTF=y") {
		t.Fatalf("expected target to be found")
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close reader: %v", err)
	}
	reader, err = gzip.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	if checkConfigFromReader(reader, "CONFIG_NOT_PRESENT=y") {
		t.Fatalf("did not expect missing target to be found")
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close reader: %v", err)
	}
}

func TestTriggerAppLaunchUsesResolvedActivity(t *testing.T) {
	originalExec := execCommand
	defer func() { execCommand = originalExec }()

	var lastCmd string
	execCommand = func(name string, args ...string) *exec.Cmd {
		cmdLine := name + " " + strings.Join(args, " ")
		lastCmd = cmdLine
		switch {
		case strings.Contains(cmdLine, "cmd package resolve-activity --brief"):
			return exec.Command("sh", "-c", "printf 'com.example/.MainActivity'")
		case strings.Contains(cmdLine, "am start -n"):
			return exec.Command("sh", "-c", "true")
		default:
			return exec.Command("sh", "-c", "true")
		}
	}

	if err := TriggerAppLaunch("com.example"); err != nil {
		t.Fatalf("TriggerAppLaunch failed: %v", err)
	}
	if !strings.Contains(lastCmd, "am start -n") {
		t.Fatalf("expected am start command, got %q", lastCmd)
	}
}
