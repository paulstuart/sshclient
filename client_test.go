package sshclient

import (
	"fmt"
	"os"
	"testing"
)

func TestSshClient(t *testing.T) {
	host := os.Getenv("SSH_HOST")
	if len(host) == 0 {
		t.Error("Error: SSH_HOST not set")
	}
	username := os.Getenv("SSH_USERNAME")
	if len(username) == 0 {
		t.Error("Error: SSH_USERNAME not set")
	}
	password := os.Getenv("SSH_PASSWORD")
	if len(password) == 0 {
		t.Error("Error: SSH_PASSWORD not set")
	}
	cmd := "hostname"
	timeout := 5
	host += ":22"
	rc, stdout, stderr, err := Exec(host, username, password, cmd, timeout)
	if err != nil {
		t.Error("ssh connect error:", err)
	}
	if rc > 0 {
		t.Error("ssh execution error:", stderr)
	} else if len(stderr) > 0 {
		t.Error("ssh execution error:", stderr)
	} else {
		fmt.Println("client returned:", stdout)
	}
}

func TestSshTimeout(t *testing.T) {
	host := os.Getenv("SSH_HOST")
	if len(host) == 0 {
		t.Error("Error: SSH_HOST not set")
	}
	username := os.Getenv("SSH_USERNAME")
	if len(username) == 0 {
		t.Error("Error: SSH_USERNAME not set")
	}
	password := os.Getenv("SSH_PASSWORD")
	if len(password) == 0 {
		t.Error("Error: SSH_PASSWORD not set")
	}
	cmd := "sleep 10"
	timeout := 5
	host += ":22"
	rc, stdout, stderr, err := Exec(host, username, password, cmd, timeout)
	if err != nil {
		t.Error("ssh connect error:", err)
	}
	if rc > 0 {
		t.Error("ssh execution error:", stderr)
	} else if len(stderr) > 0 {
		t.Error("ssh execution error:", stderr)
	} else {
		fmt.Println("client returned:", stdout)
	}
}

