// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Modify by linuz.ly

package sshclient

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh"
	"fmt"
	"log"
	"time"
)

type clientPassword string

func (p clientPassword) Password(user string) (string, error) {
	return string(p), nil
}

type Results struct {
	rc     int
	stdout string
	stderr string
}

func exec(server, username, password, cmd string, c chan Results) {
	// To authenticate with the remote server you must pass at least one
	// implementation of ClientAuth via the Auth field in ClientConfig.
	// Currently only the "password" authentication method is supported.

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.ClientAuth{
			// ClientAuthPassword wraps a ClientPassword implementation
			// in a type that implements ClientAuth.
			ssh.ClientAuthPassword(clientPassword(password)),
		},
	}
	client, err := ssh.Dial("tcp", server, config)
	if err != nil {
		panic("Failed to dial: " + err.Error())
	}

	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	defer client.Close()

	// Create a session
	session, err := client.NewSession()
	if err != nil {
		log.Fatalf("unable to create session: %s", err)
	}
	defer session.Close()

	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}
	// Request pseudo terminal
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		log.Fatalf("request for pseudo terminal failed: %s", err)
	}

	var stdout,stderr bytes.Buffer
	//var stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	rc := 0
	if err := session.Run(cmd); err != nil {
		if ugh, ok := err.(*ssh.ExitError); ok {
			rc = ugh.Waitmsg.ExitStatus()
		}
	}
	c <- Results{rc, stdout.String(), stderr.String()}
}

func Exec(server, username, password, cmd string, timeout int) (int, string, string) {
	c := make(chan Results)
	go exec(server, username, password, cmd, c)
	var r Results
	for {
		select {
		case r = <-c:
	        return r.rc, r.stdout, r.stderr
		case <-time.After(time.Duration(timeout) * time.Second):
			fmt.Println("You're too slow.")
			return -1,"",""
		}

	}
}
