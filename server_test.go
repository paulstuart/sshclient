// build notready

// adapted from https://gist.github.com/jpillora/b480fde82bff51a06238
package sshclient

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

const (
	testUsername    = "joebob"
	testPassword    = "howdy!"
	defaultTestPort = 12200
)

var (
	tempDir     string
	testPort    int
	testKeyFile = "~/.ssh/id_rsa"
)

func testOptions(t *testing.T) *ServerOptions {
	return &ServerOptions{
		Username: "joebob",
		Password: "howdy!",
		Port:     &testPort,
		Logger:   t,
		KeyFile:  "~/.ssh/id_rsa",
	}
}

func testServer(t *testing.T, options *ServerOptions) {
	t.Helper()
	if options == nil {
		options = testOptions(t)
	}
	close, err := FakeServer(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(close)
	t.Logf("test server running")
}

func TestLocal(t *testing.T) {
	//t.Skip("fix test server")
	testServer(t, nil)

	cmd := "hostname"
	timeout := 5
	t.Logf("server port is: %d\n", testPort)
	host := fmt.Sprintf("localhost:%d", testPort)
	fmt.Println("exec ssh")
	r, err := ExecPassword(host, testUsername, testPassword, cmd, timeout)
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

func TestLocalError(t *testing.T) {
	//t.Skip("fix test server")
	cmd := "foo" // command is ignored, so what ev er
	stdout := "meh"
	stderr := "we have a failure to communicate"
	rc := 23
	options := testOptions(t)
	options.Exec = &MockHandler{RC: rc, Stdout: stdout, Stderr: stderr}
	testServer(t, options)
	fmt.Println("test server running")

	timeout := 1
	host := fmt.Sprintf("localhost:%d", testPort)
	fmt.Println("exec ssh")
	r, err := ExecPassword(host, testUsername, testPassword, cmd, timeout)
	if err != nil {
		if err, ok := err.(*ssh.ExitError); ok {
			t.Logf("got expected error: %+v", err)
		} else {
			t.Errorf("ssh connect error (%T): %+v", err, err)
		}
	}
	if r.RC != rc {
		t.Errorf("rc want: %d -- got: %d\n", rc, r.RC)
	}
	if r.Stdout != stdout {
		t.Errorf("stdout want: %q -- got: %q\n", stdout, r.Stdout)
	}
	if r.Stderr != stderr {
		t.Errorf("stderr want: %q -- got: %q\n", stderr, r.Stderr)
	}
}

func TestLocalBash(t *testing.T) {
	//t.Skip("not yet")
	cmd := "hostname" // command is ignored, so what ev er
	stdout, err := os.Hostname()
	if err != nil {
		t.Fatalf("error getting hostname: %+v\n", err)
	}
	stderr := ""
	rc := 0
	options := testOptions(t)
	options.Exec = &BashHandler{}
	testServer(t, options)

	timeout := 1
	host := fmt.Sprintf("localhost:%d", testPort)
	fmt.Println("exec ssh")
	r, err := ExecPassword(host, testUsername, testPassword, cmd, timeout)
	if err != nil {
		if err, ok := err.(*ssh.ExitError); ok {
			t.Logf("got expected error: %+v", err)
		} else {
			t.Errorf("ssh connect error (%T): %+v", err, err)
		}
	}
	t.Logf("REPLY: %+v\n", r)
	if r.RC != rc {
		t.Errorf("rc want: %d -- got: %d\n", rc, r.RC)
	}
	out := strings.TrimSpace(r.Stdout)
	if out != stdout {
		t.Errorf("stdout want: %q -- got: %q\n", stdout, out)
	}
	if r.Stderr != stderr {
		t.Errorf("stderr want: %q -- got: %q\n", stderr, r.Stderr)
	}
}

func TestLocalBashError(t *testing.T) {
	t.Skip("not yet")
	cmd := "foo" // this should be an invalid command
	stdout := "bash: foo: command not found"
	stderr := ""
	rc := 127
	options := testOptions(t)
	options.Exec = &BashHandler{}
	testServer(t, options)

	timeout := 1
	host := fmt.Sprintf("localhost:%d", testPort)
	r, err := ExecPassword(host, testUsername, testPassword, cmd, timeout)
	if err != nil {
		if err, ok := err.(*ssh.ExitError); ok {
			t.Logf("got expected error: %+v", err)
		} else {
			t.Errorf("ssh connect error (%T): %+v", err, err)
		}
	}
	t.Logf("REPLY: %+v\n", r)
	if r.RC != rc {
		t.Errorf("rc want: %d -- got: %d\n", rc, r.RC)
	}
	out := strings.TrimSpace(r.Stdout)
	if out != stdout {
		t.Errorf("stdout want: %q -- got: %q\n", stdout, out)
	}
	if r.Stderr != stderr {
		t.Errorf("stderr want: %q -- got: %q\n", stderr, r.Stderr)
	}
}
