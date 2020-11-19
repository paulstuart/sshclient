// Copyright 2016-2020 Paul Stuart. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sshclient

import (
	"os"
	"strings"
	"testing"

	"github.com/joho/godotenv"
)

const (
	DefaultEnvFile = "testing.env"
	EnvFileEnv     = "ENV_FILE" // to override DefaultEnvFile
)

var (
	host, username, password, keyfile, keytext string
)

// Using envs to avoid accidentally baking creds into code
func init() {
	envFile := os.Getenv(EnvFileEnv)
	if envFile == "" {
		envFile = DefaultEnvFile
	}
	_ = godotenv.Load(envFile)

	host = os.Getenv("SSH_HOST")
	if host == "" {
		panic("Error: SSH_HOST not set")
	}

	username = os.Getenv("SSH_USERNAME")
	if username == "" {
		panic("Error: SSH_USERNAME not set")
	}

	password = os.Getenv("SSH_PASSWORD")
	if password == "" {
		panic("Error: SSH_PASSWORD not set")
	}

	keyfile = os.Getenv("SSH_PRIVATE")
	if keyfile == "" {
		panic("Error: SSH_PRIVATE not set (private keyfile)")
	}

	keytext = os.Getenv("SSH_KEY")
	if keyfile == "" {
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
	_, err = Run(client, cmd)
	if err != nil {
		t.Fatal("keyauth run error:", err)
	}
}

func TestSSHKeyAuth(t *testing.T) {
	t.Skip("bad envs?")
	client, err := DialKey(host, username, keytext, 5)
	if err != nil {
		t.Fatal("key auth dial error:", err)
	}
	cmd := "logname"
	r, err := Run(client, cmd)
	if err != nil {
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
	client.Buffered()
	_ = client.Terminal()
	cmd := "logname"
	r, err := Run(client, cmd)
	if err != nil {
		t.Fatal("keyfile auth run error:", err)
	}
	if r.Stderr != "" {
		t.Log(r.Stderr)
	}
	if strings.TrimSpace(r.Stdout) != username {
		t.Fatalf("want: %q -- got: %q", username, r.Stdout)
	}
}

func TestSSHAgent(t *testing.T) {
	client, err := DialAgent(host, username, 5)
	if err != nil {
		t.Fatal("agent dial error:", err)
	}
	client.Buffered()

	cmd := "logname"
	r, err := Run(client, cmd)
	if err != nil {
		t.Fatal("key auth run error:", err)
	}
	if strings.TrimSpace(r.Stdout) != username {
		t.Fatal("ssh-agent command failed. expected", username, "got", r.Stdout)
	}
}

func TestSSHClient(t *testing.T) {
	t.Skip("need test ssh server")
	cmd := "hostname"
	timeout := 5
	r, err := ExecPassword(host, username, password, cmd, timeout)
	if err != nil {
		t.Fatal("ssh connect error:", err)
	}
	if r.RC > 0 {
		t.Error("ssh execution error:", r.Stderr)
	} else if len(r.Stderr) > 0 {
		t.Error("ssh execution error:", r.Stderr)
	} else {
		t.Log("client returned:", r.Stdout)
	}
}

func TestSSHStderr(t *testing.T) {
	cmd := "lsX"
	timeout := 5
	r, _ := ExecPassword(host, username, password, cmd, timeout)
	if len(r.Stdout) > 0 {
		t.Log("ssh stdout", r.Stdout)
	}
	if len(r.Stderr) > 0 {
		t.Log("ssh stderr:", r.Stderr)
	}
}

func TestSSHTimeout(t *testing.T) {
	cmd := "sleep 10"
	timeout := 5
	r, err := ExecPassword(host, username, password, cmd, timeout)
	if err == nil {
		t.Error("ssh timeout failed")
	}
	if r.RC > 0 {
		t.Error("ssh execution error:", r.Stderr)
	} else if len(r.Stderr) > 0 {
		t.Error("ssh execution error:", r.Stderr)
	}
}

// TODO: makr this test (and others) self contained with a test ssh server
const (
	scpTestFile = "_TESTING_SCP_.txt"
	scpTestDir  = "/tmp/foo"
)

func TestSCP(t *testing.T) {
	s, err := DialKeyFile(host, username, keyfile, 5)
	if err != nil {
		t.Fatal(err)
	}
	err = s.CopyFile(scpTestFile, scpTestDir)
	if err != nil {
		t.Fatal("copy error:", err)
	}
}
