// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Modify by linuz.ly

package sshclient

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	termType = "xterm"
)

type clientPassword string

func (p clientPassword) Password(user string) (string, error) {
	return string(p), nil
}

type Results struct {
	err    error
	rc     int
	stdout string
	stderr string
}

type keychain struct {
	keys []ssh.Signer
}

func (k *keychain) PrivateKey(file string) error {
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	key, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		return err
	}
	k.keys = append(k.keys, key)
	return nil
}

func KeyAuth(file string) (ssh.AuthMethod, error) {
	k := new(keychain)
	err := k.PrivateKey(file)
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(k.keys...), nil
}

func DialKey(server, username, keyfile string, timeout int) (*ssh.Client, error) {
	keyauth, err := KeyAuth(keyfile)
	if err != nil {
		return nil, err
	}
	return DialSsh(server, username, timeout, keyauth)
}

func DialPassword(server, username, password string, timeout int) (*ssh.Client, error) {
	return DialSsh(server, username, timeout, ssh.Password(password))
}

func DialSsh(server, username string, timeout int, auth ...ssh.AuthMethod) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User: username,
		Auth: auth,
	}
	conn, err := net.DialTimeout("tcp", server, time.Duration(timeout)*time.Second)
	if err != nil {
		return nil, err
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, server, config)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

func Run(client *ssh.Client, cmd string) Results {
	session, err := client.NewSession()
	if err != nil {
		return Results{err: err}
	}
	defer session.Close()

	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}
	// Request pseudo terminal
	if err := session.RequestPty(termType, 80, 40, modes); err != nil {
		return Results{err: fmt.Errorf("request for pseudo terminal failed: %s", err.Error())}
	}

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	rc := 0
	if err := session.Run(cmd); err != nil {
		if err2, ok := err.(*ssh.ExitError); ok {
			rc = err2.Waitmsg.ExitStatus()
		}
	}
	return Results{nil, rc, stdout.String(), stderr.String()}
}

func Exec(server, username, password, cmd string, timeout int) (rc int, stdout, stderr string, err error) {
	var client *ssh.Client
	client, err = DialPassword(server, username, password, timeout)
	if err != nil {
		return
	}
	defer client.Close()

	c := make(chan Results)
	go func() {
		c <- Run(client, cmd)
	}()

	for {
		select {
		case r := <-c:
			err, rc, stdout, stderr = r.err, r.rc, r.stdout, r.stderr
			return
		case <-time.After(time.Duration(timeout) * time.Second):
			err = fmt.Errorf("Command timed out after %d seconds", timeout)
			return
		}
	}
}
