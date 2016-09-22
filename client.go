// Copyright 2016 Paul Stuart. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sshclient

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
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

// Results comprises all info resulting from running a command via ssh
type Results struct {
	Err    error  // internal or communication errors
	RC     int    // the result code of the command itself
	Stdout string // stdout from the command
	Stderr string // stderr from the command
}

// Session allows for multiple commands to be run against an ssh connection
type Session struct {
	client   *ssh.Client
	ssh      *ssh.Session
	out, err bytes.Buffer
}

type keychain struct {
	keys []ssh.Signer
}

// Close closes the ssh session
func (s *Session) Close() {
	s.ssh.Close()
	if s.client != nil {
		s.client.Close()
	}
}

// Clear clears the stdout and stderr buffers
func (s *Session) Clear() {
	s.out.Reset()
	s.err.Reset()
}

// Shell opens an command shell on the remote host
func (s *Session) Shell() error {
	return s.ssh.Shell()
}

func (k *keychain) PrivateKey(text []byte) error {
	key, err := ssh.ParsePrivateKey(text)
	if err != nil {
		return err
	}
	k.keys = append(k.keys, key)
	return nil
}

func (k *keychain) PrivateKeyFile(file string) error {
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	return k.PrivateKey(buf)
}

func keyAuth(key string) (ssh.AuthMethod, error) {
	k := new(keychain)
	if err := k.PrivateKey([]byte(key)); err != nil {
		return nil, err
	}
	return ssh.PublicKeys(k.keys...), nil
}

func keyFileAuth(file string) (ssh.AuthMethod, error) {
	k := new(keychain)
	if err := k.PrivateKeyFile(file); err != nil {
		return nil, err
	}
	return ssh.PublicKeys(k.keys...), nil
}

//DialKey will open an ssh session using an key key
func DialKey(server, username, key string, timeout int) (*Session, error) {
	auth, err := keyAuth(key)
	if err != nil {
		return nil, err
	}
	return DialSSH(server, username, timeout, auth)
}

//DialKeyFile will open an ssh session using an key key stored in keyfile
func DialKeyFile(server, username, keyfile string, timeout int) (*Session, error) {
	auth, err := keyFileAuth(keyfile)
	if err != nil {
		return nil, err
	}
	return DialSSH(server, username, timeout, auth)
}

//DialPassword will open an ssh session using the specified password
func DialPassword(server, username, password string, timeout int) (*Session, error) {
	return DialSSH(server, username, timeout, ssh.Password(password))
}

//DialSSH will open an ssh session using the specified authentication
func DialSSH(server, username string, timeout int, auth ...ssh.AuthMethod) (*Session, error) {
	config := &ssh.ClientConfig{
		User: username,
		Auth: auth,
	}
	if strings.Index(server, ":") < 0 {
		server += ":22"
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

// NewSession will open an ssh session using the provided connection
func NewSession(client *ssh.Client) (*Session, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}

	s := &Session{ssh: session, client: client}

	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,      // disable echoing
		ssh.TTY_OP_ISPEED: 115200, // input speed  = 115.2kbps
		ssh.TTY_OP_OSPEED: 115200, // output speed = 115.2kbps
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

// Run will run a command in the session
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

func exec(session *Session, cmd string, timeout int) (rc int, stdout, stderr string, err error) {
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

// ExecPassword will run a single command using the given password
func ExecPassword(server, username, password, cmd string, timeout int) (rc int, stdout, stderr string, err error) {
	var session *Session
	session, err = DialPassword(server, username, password, timeout)
	if err != nil {
		return
	}
	return exec(session, cmd, timeout)
}

// ExecText will run a single command using the given key
func ExecText(server, username, keytext, cmd string, timeout int) (rc int, stdout, stderr string, err error) {
	var session *Session
	session, err = DialKey(server, username, keytext, timeout)
	if err != nil {
		return
	}
	return exec(session, cmd, timeout)
}
