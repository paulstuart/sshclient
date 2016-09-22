// Copyright 2016 Paul Stuart. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sshclient

import (
	"os"
	"strings"
	"testing"
)

var (
	host, username, password, keyfile, keytext string
)

func init() {
	host = os.Getenv("SSH_HOST")
	if len(host) == 0 {
		panic("Error: SSH_HOST not set")
	}

	username = os.Getenv("SSH_USERNAME")
	if len(username) == 0 {
		panic("Error: SSH_USERNAME not set")
	}

	password = os.Getenv("SSH_PASSWORD")
	if len(password) == 0 {
		panic("Error: SSH_PASSWORD not set")
	}

	keyfile = os.Getenv("SSH_PRIVATE")
	if len(keyfile) == 0 {
		panic("Error: SSH_PRIVATE not set (private keyfile)")
	}

	keytext = os.Getenv("SSH_KEY")
	if len(keyfile) == 0 {
		panic("Error: SSH_KEY not set (private key variable)")
	}
}

func TestSSHKey(t *testing.T) {
	keyauth, err := keyFileAuth(keyfile)
	if err != nil {
		t.Fatal("keyauth error:", err)
	}
	client, err := DialSSH(host, username, 5, keyauth)
	if err != nil {
		t.Fatal("keyauth dial error:", err)
	}
	cmd := "uptime"
	r := Run(client, cmd)
	if r.Err != nil {
		t.Fatal("keyauth run error:", err)
	}
}

func TestSSHKeyAuth(t *testing.T) {
	client, err := DialKey(host, username, keytext, 5)
	if err != nil {
		t.Fatal("key auth dial error:", err)
	}
	cmd := "logname"
	r := Run(client, cmd)
	if r.Err != nil {
		t.Fatal("key auth run error:", err)
	}
	if strings.TrimSpace(r.Stdout) != username {
		t.Fatal("keyauth command failed. expected", username, "got", r.Stdout)
	}
}

func TestSSHKeyFileAuth(t *testing.T) {
	client, err := DialKeyFile(host, username, keyfile, 5)
	if err != nil {
		t.Fatal("keyfile auth dial error:", err)
	}
	cmd := "logname"
	r := Run(client, cmd)
	if r.Err != nil {
		t.Fatal("keyfile auth run error:", err)
	}
	if strings.TrimSpace(r.Stdout) != username {
		t.Fatal("keyfile auth command failed. expected", username, "got", r.Stdout)
	}
}

func TestSSHClient(t *testing.T) {
	cmd := "hostname"
	timeout := 5
	rc, stdout, stderr, err := ExecPassword(host, username, password, cmd, timeout)
	if err != nil {
		t.Error("ssh connect error:", err)
	}
	if rc > 0 {
		t.Error("ssh execution error:", stderr)
	} else if len(stderr) > 0 {
		t.Error("ssh execution error:", stderr)
	} else {
		t.Log("client returned:", stdout)
	}
}

func TestSSHStderr(t *testing.T) {
	cmd := "lsX"
	timeout := 5
	_, stdout, stderr, _ := ExecPassword(host, username, password, cmd, timeout)
	if len(stdout) > 0 {
		t.Log("ssh stdout", stdout)
	}
	if len(stderr) > 0 {
		t.Log("ssh stderr:", stderr)
	}
}

func TestSSHTimeout(t *testing.T) {
	cmd := "sleep 10"
	timeout := 5
	rc, _, stderr, err := ExecPassword(host, username, password, cmd, timeout)
	if err == nil {
		t.Error("ssh timeout failed")
	}
	if rc > 0 {
		t.Error("ssh execution error:", stderr)
	} else if len(stderr) > 0 {
		t.Error("ssh execution error:", stderr)
	}
}
