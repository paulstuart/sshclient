// Copyright 2016 Paul Stuart. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sshclient

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Results comprises the results from running a command via ssh
type Results struct {
	RC     int    // the result code of the command itself
	Stdout string // stdout from the command
	Stderr string // stderr from the command
}

type CmdError struct {
	RC     int
	Stdout string
	Stderr string
}

func (e CmdError) Error() string {
	return fmt.Sprintf("rc:%d stdout:%q stderr:%q", e.RC, e.Stdout, e.Stderr)
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

//DialKey will open an ssh session using a private key
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

// DialAgent makes a ssh connection with credentials from ssh-agent
func DialAgent(server, username string, timeout int) (*Session, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("can't connect to ssh-agent: %w", err)
	}

	agentClient := agent.NewClient(conn)
	config := &ssh.ClientConfig{
		User:    username,
		Timeout: time.Duration(timeout) * time.Second,
		Auth: []ssh.AuthMethod{
			// Use a callback rather than PublicKeys so we only consult the
			// agent once the remote server wants it.
			ssh.PublicKeysCallback(agentClient.Signers),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: make this secure
	}

	return DialConfigSSH(server, username, config)
}

//DialConfigSSH will open an ssh session using the given config
func DialConfigSSH(server, username string, config *ssh.ClientConfig) (*Session, error) {
	if !strings.Contains(server, ":") {
		server += ":22"
	}
	conn, err := net.DialTimeout("tcp", server, config.Timeout)
	if err != nil {
		return nil, err
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, server, config)
	if err != nil {
		return nil, err
	}
	return NewSession(ssh.NewClient(c, chans, reqs))
}

//DialSSH will open an ssh session using the specified authentication
func DialSSH(server, username string, timeout int, auth ...ssh.AuthMethod) (*Session, error) {
	if len(auth) == 0 {
		panic("no auth!")
	}
	config := &ssh.ClientConfig{
		User:            username,
		Auth:            auth,
		Timeout:         time.Duration(timeout) * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: find cleaner way for this
	}
	return DialConfigSSH(server, username, config)
}

// NewSession will open an ssh session using the provided connection
func NewSession(client *ssh.Client) (*Session, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}

	s := &Session{ssh: session, client: client}
	return s, nil
}

// Buffered insures that command output is captured
func (s *Session) Buffered() {
	s.ssh.Stdout = &s.out
	s.ssh.Stderr = &s.err
}

// Terminal emulates a terminal
func (s *Session) Terminal() error {
	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,      // disable echoing
		ssh.TTY_OP_ISPEED: 115200, // input speed  = 115.2kbps
		ssh.TTY_OP_OSPEED: 115200, // output speed = 115.2kbps
	}
	// Request pseudo terminal
	if err := s.ssh.RequestPty("xterm", 80, 40, modes); err != nil {
		s.client.Close()
		return err
	}
	return nil
}

// Run will run a command in the session
func Run(session *Session, cmd string) (Results, error) {
	var rc int
	var err error
	if err = session.ssh.Run(cmd); err != nil {
		if err2, ok := err.(*ssh.ExitError); ok {
			rc = err2.Waitmsg.ExitStatus()
		}
	}
	return Results{rc, session.out.String(), session.err.String()}, err
}

// ExecPassword will run a single command using the given password
func ExecPassword(server, username, password, cmd string, timeout int) (Results, error) {
	session, err := DialPassword(server, username, password, timeout)
	if err != nil {
		return Results{}, err
	}
	session.Buffered()
	return Run(session, cmd)
}

// ExecText will run a single command using the given key
func ExecText(server, username, keytext, cmd string, timeout int) (Results, error) {
	session, err := DialKey(server, username, keytext, timeout)
	if err != nil {
		return Results{}, err
	}
	session.Buffered()
	return Run(session, cmd)
}

// ExecAgent will run a single command using ssh-agent
func ExecAgent(server, username, cmd string, timeout int) (Results, error) {
	session, err := DialAgent(server, username, timeout)
	if err != nil {
		return Results{}, err
	}
	session.Buffered()
	return Run(session, cmd)
}

// CopyFile scp's filename to dest on the remote host
func (s *Session) CopyFile(filename, dest string) error {
	info, err := os.Stat(filename)
	if err != nil {
		return err
	}
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return s.Copy(f, filename, dest, info.Size(), info.Mode())
}

// Copy scp's the reader contents named filename to dest on the remote host
func (s *Session) Copy(r io.Reader, filename, destination string, size int64, mode os.FileMode) error {
	w, err := s.ssh.StdinPipe()
	if err != nil {
		return err
	}

	// capture stderr
	s.Buffered()

	cmd := fmt.Sprintf("/usr/bin/env scp -tq %s", destination)
	if err := s.ssh.Start(cmd); err != nil {
		w.Close()
		return err
	}

	errors := make(chan error)

	go func() {
		errors <- s.ssh.Wait()
	}()

	// send the SCP Create command
	fmt.Fprintf(w, "C%#o %d %s\n", mode, size, filename)
	if _, err := io.Copy(w, r); err != nil {
		w.Close()
		return fmt.Errorf("copy error: %w", err)
	}
	// send end of command marker
	fmt.Fprint(w, "\x00")
	w.Close()

	err = <-errors

	if err == nil {
		return nil
	}

	// get more details about the error
	if serr, ok := err.(*ssh.ExitError); ok {
		rc := serr.Waitmsg.ExitStatus()
		stderr := s.err.String()
		stdout := s.out.String()
		// scp errors start with a null byte and are separated by "markers",
		// values 0, 1, 2 -- for ok, warning, error (respectively)
		// I believe we only care about the first line
		if len(stdout) > 2 {
			b := []byte(stdout)
			// skip the leading 0
			b = b[1:]
			fn := func(c rune) bool {
				return c < 3
			}
			parts := bytes.FieldsFunc(b, fn)
			stdout = string(parts[0])
			stdout = strings.TrimRight(stdout, "\n")
		}
		return CmdError{rc, stdout, stderr}
	}
	return err
}
