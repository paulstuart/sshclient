package sshclient

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

// Logger accomodates testing.T as a logger
type Logger interface {
	Log(...interface{})
	Logf(string, ...interface{})
}

// ExecHandler abstracts handling of ssh "exec"
type ExecHandler interface {
	Exec(string) (int, error)
	SetChannel(ssh.Channel)
}

// ServerOptions control the ssh server behavior
type ServerOptions struct {
	Hostname string
	Username string
	Password string
	KeyFile  string
	KeyBytes []byte
	Port     *int
	Logger   Logger
	Exec     ExecHandler
}

// MockHandler allows faking expected behavior
type MockHandler struct {
	RC     int
	Stdout string
	Stderr string
	ch     ssh.Channel
}

// SetChannel makes this an ExecHandler
func (m *MockHandler) SetChannel(ch ssh.Channel) {
	m.ch = ch
}

// Exec makes this an ExecHandler
func (m *MockHandler) Exec(_ string) (int, error) {
	fmt.Fprint(m.ch, m.Stdout)
	fmt.Fprint(m.ch.Stderr(), m.Stderr)
	return m.RC, nil
}

// EchoHandler is the default dummy handler
type EchoHandler struct {
	ch ssh.Channel
}

// SetChannel makes this an ExecHandler
func (m *EchoHandler) SetChannel(ch ssh.Channel) {
	m.ch = ch
}

// Exec makes this an ExecHandler
func (m *EchoHandler) Exec(cmd string) (int, error) {
	fmt.Fprintf(m.ch, "command is: %q", cmd)
	return 0, nil
}

// BashHandler runs a command in bash
type BashHandler struct {
	ch ssh.Channel
}

// SetChannel makes this an ExecHandler
func (m *BashHandler) SetChannel(ch ssh.Channel) {
	m.ch = ch
}

// Exec makes this an ExecHandler
func (m *BashHandler) Exec(cmd string) (int, error) {
	basher := exec.Command("bash", "--noprofile", "--norc", "-c", cmd)

	basher.Stdout = m.ch
	basher.Stderr = m.ch.Stderr()

	_, err := pty.Start(basher)
	if err != nil {
		return 0, fmt.Errorf("could not start pty: %w", err)
	}

	status, err := basher.Process.Wait()
	if err != nil {
		return basher.ProcessState.ExitCode(), fmt.Errorf("bash wait error: %w", err)
	}

	return status.ExitCode(), nil

}

type nonlLogger struct{}

// Log makes this a Logger
func (n nonlLogger) Log(_ ...interface{}) {}

// Logf makes this a Logger
func (n nonlLogger) Logf(_ string, _ ...interface{}) {}

// Server is a fake ssh server for unit testing
func Server(options *ServerOptions) (func(), error) {
	if options.Exec == nil {
		options.Exec = &EchoHandler{}
	}
	if options.Logger == nil {
		options.Logger = nonlLogger{}
	}
	if options.Hostname == "" {
		options.Hostname = "localhost"
	}
	config := &ssh.ServerConfig{}
	if options.Password != "" {
		//Define a function to run when a client attempts a password login
		config.PasswordCallback = func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in a production setting.
			if c.User() == options.Username && string(pass) == options.Password {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		}
		// You may also explicitly allow anonymous client authentication, though anon bash
		// sessions may not be a wise idea
		// NoClientAuth: true,
	}

	// You can generate a keypair with 'ssh-keygen -t rsa'
	if options.KeyFile != "" {
		if strings.HasPrefix(options.KeyFile, "~/") {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("can't find home dir to find `~`: %w", err)
			}
			options.KeyFile = filepath.Join(home, options.KeyFile[2:])
		}

		privateBytes, err := ioutil.ReadFile(options.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key (%s): %v", options.KeyFile, err)
		}

		private, err := ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}

		config.AddHostKey(private)
	}

	if len(options.KeyBytes) > 0 {
		private, err := ssh.ParsePrivateKey(options.KeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}

		config.AddHostKey(private)
	}

	// to ensure we can start, by default we'll expect no port to be specified
	// to avoid port conflicts, so we bind to :0 and report back the port chosen
	var listenPort int
	if options.Port == nil {
		options.Port = &listenPort
	}
	addr := fmt.Sprintf("%s:%d", options.Hostname, listenPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	*(options.Port) = listener.Addr().(*net.TCPAddr).Port
	addr = fmt.Sprintf("%s:%d", options.Hostname, *(options.Port))

	listening := true
	go func() {
		options.Logger.Logf("Listening on %s...\n", addr)
		for {
			tcpConn, err := listener.Accept()
			if err != nil {
				if !listening {
					break
				}
				options.Logger.Logf("Failed to accept incoming connection (%s)", err)
				continue
			}
			// Before use, a handshake must be performed on the incoming net.Conn.
			sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
			if err != nil {
				options.Logger.Logf("Failed to handshake (%s)", err)
				continue
			}

			options.Logger.Logf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
			// Discard all global out-of-band Requests
			go ssh.DiscardRequests(reqs)
			// Accept all channels
			go handleChannels(chans, options.Exec, options.Logger)
		}
	}()

	close := func() {
		options.Logger.Logf("closing listener")
		listening = false
		listener.Close()
	}
	return close, nil
}

func handleChannels(chans <-chan ssh.NewChannel, hndlr ExecHandler, logger Logger) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go handleChannel(newChannel, hndlr, logger)
	}
}

func handleChannel(newChannel ssh.NewChannel, hndlr ExecHandler, logger Logger) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		logger.Logf("Could not accept channel (%s)", err)
		return
	}
	hndlr.SetChannel(connection)

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range requests {
			actionOk := true
			switch req.Type {
			case "shell":
				//  only accept the default shell,
				// (i.e. no command in the Payload)
				actionOk = len(req.Payload) == 0
				/*
					case "pty-req":
						termLen := req.Payload[3]
						w, h := parseDims(req.Payload[termLen+4:])
						SetWinsize(bashf.Fd(), w, h)
						// Responding true (OK) here will let the client
						// know we have a pty ready for input
						req.Reply(true, nil)
					case "window-change":
						w, h := parseDims(req.Payload)
						SetWinsize(bashf.Fd(), w, h)
				*/
			case "exec":
				cmd := string(req.Payload[4:])
				rc, err := hndlr.Exec(cmd)
				if err != nil {
					logger.Logf("handler exec error: %v\n", err)
					actionOk = false
				}
				logger.Logf("exec rc: %d\n", rc)
				_, err = connection.SendRequest("exit-status", false, []byte{0, 0, 0, byte(rc)})
				if err != nil {
					logger.Logf("SendRequest error: %+v", err)
				}
				req.Reply(actionOk, nil)
				connection.Close()

			default:
				logger.Logf("unhandled request type: %s\n", req.Type)
			}
			if req.WantReply {
				req.Reply(actionOk, nil)
			}
		}
		logger.Log("end of session requests")
	}()
}

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}
