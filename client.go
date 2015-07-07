// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Modify by linuz.ly

package sshclient

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
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
	Err    error
	RC     int
	Stdout string
	Stderr string
}

type Session struct {
	client   *ssh.Client
	ssh      *ssh.Session
	out, err bytes.Buffer
}

type keychain struct {
	keys []ssh.Signer
}

func (s *Session) Close() {
	s.ssh.Close()
	if s.client != nil {
		s.client.Close()
	}
}

func (s *Session) Reset() {
	s.out.Reset()
	s.err.Reset()
}

func (s *Session) Shell() error {
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	if err := s.ssh.RequestPty("xterm", 80, 40, modes); err != nil {
		log.Fatalf("request for pseudo terminal failed: %s", err)
	}

	return s.ssh.Shell()
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

func DialKey(server, username, keyfile string, timeout int) (*Session, error) {
	keyauth, err := KeyAuth(keyfile)
	if err != nil {
		return nil, err
	}
	return DialSsh(server, username, timeout, keyauth)
}

func DialPassword(server, username, password string, timeout int) (*Session, error) {
	return DialSsh(server, username, timeout, ssh.Password(password))
}

func DialSsh(server, username string, timeout int, auth ...ssh.AuthMethod) (*Session, error) {
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
	return NewSession(ssh.NewClient(c, chans, reqs))
}

func NewSession(client *ssh.Client) (*Session, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}

	s := &Session{ssh: session, client: client}

	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}
	// Request pseudo terminal
	if err := session.RequestPty(termType, 80, 40, modes); err != nil {
		client.Close()
		return nil, err
	}

	session.Stdout = &s.out
	session.Stderr = &s.err
	return s, nil
}

func Run(session *Session, cmd string) Results {
	var rc int
	var err error
	if err = session.ssh.Run(cmd); err != nil {
		if err2, ok := err.(*ssh.ExitError); ok {
			rc = err2.Waitmsg.ExitStatus()
		}
	}
	return Results{err, rc, session.out.String(), session.err.String()}
}

func Exec(server, username, password, cmd string, timeout int) (rc int, stdout, stderr string, err error) {
	session, err := DialPassword(server, username, password, timeout)
	if err != nil {
		return
	}
	defer session.Close()

	c := make(chan Results)
	go func() {
		c <- Run(session, cmd)
	}()

	for {
		select {
		case r := <-c:
			err, rc, stdout, stderr = r.Err, r.RC, r.Stdout, r.Stderr
			return
		case <-time.After(time.Duration(timeout) * time.Second):
			err = fmt.Errorf("Command timed out after %d seconds", timeout)
			return
		}
	}
}
