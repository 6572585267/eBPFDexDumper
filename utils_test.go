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

	if err := TriggerAppLaunch("com.example", 1); err != nil {
		t.Fatalf("TriggerAppLaunch failed: %v", err)
	}
	if !strings.Contains(lastCmd, "am start -n") {
		t.Fatalf("expected am start command, got %q", lastCmd)
	}
}

func TestTriggerAppLaunchMonkeyFallback(t *testing.T) {
	originalExec := execCommand
	defer func() { execCommand = originalExec }()

	var lastCmd string
	execCommand = func(name string, args ...string) *exec.Cmd {
		cmdLine := name + " " + strings.Join(args, " ")
		lastCmd = cmdLine
		switch {
		case strings.Contains(cmdLine, "cmd package resolve-activity --brief"):
			return exec.Command("sh", "-c", "false")
		case strings.Contains(cmdLine, "monkey -p"):
			return exec.Command("sh", "-c", "true")
		default:
			return exec.Command("sh", "-c", "true")
		}
	}

	if err := TriggerAppLaunch("com.example", 3); err != nil {
		t.Fatalf("TriggerAppLaunch fallback failed: %v", err)
	}
	if !strings.Contains(lastCmd, "monkey -p com.example") || !strings.Contains(lastCmd, " 3") {
		t.Fatalf("expected monkey command with count, got %q", lastCmd)
	}
}

func TestParseProcMaps(t *testing.T) {
	data := "00400000-00452000 r-xp 00000000 08:02 12345 /system/bin/app_process64\n" +
		"00652000-00653000 r--p 00052000 08:02 12345 /system/bin/app_process64\n"
	entries, err := ParseProcMaps(strings.NewReader(data))
	if err != nil {
		t.Fatalf("ParseProcMaps error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Start != 0x00400000 || entries[0].End != 0x00452000 {
		t.Fatalf("unexpected range: %#v", entries[0])
	}
	if entries[0].Perms != "r-xp" {
		t.Fatalf("unexpected perms: %s", entries[0].Perms)
	}
}

func TestDetectDexMagic(t *testing.T) {
	if DetectDexMagic([]byte("dex\n035\x00")) != "dex" {
		t.Fatalf("expected dex magic")
	}
	if DetectDexMagic([]byte("cdex001")) != "cdex" {
		t.Fatalf("expected cdex magic")
	}
	if DetectDexMagic([]byte("xxxx")) != "" {
		t.Fatalf("expected no magic")
	}
}

func TestParseDexFileSize(t *testing.T) {
	header := make([]byte, 0x40)
	size := uint32(0x12345678)
	header[0x20] = byte(size)
	header[0x21] = byte(size >> 8)
	header[0x22] = byte(size >> 16)
	header[0x23] = byte(size >> 24)
	if ParseDexFileSize(header) != size {
		t.Fatalf("expected size %x", size)
	}
}
