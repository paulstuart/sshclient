// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Modify by linuz.ly

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
    cmd := "id"
    timeout := 10
    host += ":22"
    err,rc,stdout,stderr := Exec(host, username, password, cmd, timeout)
    if err != nil {
        t.Error("ssh connect error:", err)
    }
    if rc > 0 {
        t.Error("ssh execution error:", stderr)
    }
    if len(stderr) > 0 {
        t.Error("ssh execution error:", stderr)
    }
    fmt.Println("client returned:",stdout)
}
