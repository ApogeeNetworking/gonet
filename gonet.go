package gonet

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Gonet Main Object
type Gonet struct {
	Username string
	Password string
	IP       string
	HostName string
	Model    string // 9500, 2960, N-Class
	Vendor   string
	// Enable Password if any
	Enable  string
	echo    bool
	prompt  string // Finds the Prompt # >
	input   chan *string
	stop    chan struct{}
	timeout int
	client  *ssh.Client
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	stderr  io.Reader
}

// New creates an instance of a GoNet Client
func New(host, user, pass string) *Gonet {
	g := Gonet{
		IP:       host,
		Username: user,
		Password: pass,
		input:    make(chan *string),
		stop:     make(chan struct{}),
		timeout:  30,
	}
	return &g
}

func (g *Gonet) getPass() (string, error) {
	return g.Password, nil
}

// Connect to the Device with Retries
func (g *Gonet) Connect(retries int) error {
	sshConf := &ssh.ClientConfig{
		User: g.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(g.Password),
			ssh.PasswordCallback(g.getPass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	sshConf.SetDefaults()
	// sshConf.Ciphers = []string{"chacha20-poly1305@openssh.com"}
	// Some models of devices may not have the correct ciphers
	// We could handle that hear
	sshClient, err := ssh.Dial("tcp", g.IP+":22", sshConf)
	if err != nil {
		// Before we give up on a failed handshake
		if strings.Contains(err.Error(), "handshake") {
			fmt.Println(err.Error())
			count := retries + 1
			return g.Connect(count)
		}
		return err
	}
	sshSession, err := sshClient.NewSession()
	if err != nil {
		sshClient.Conn.Close()
		return err
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	if err := sshSession.RequestPty("xterm", 0, 2000, modes); err != nil {
		sshSession.Close()
		return fmt.Errorf("request for pseudo terminal failed: %s", err)
	}

	g.client = sshClient
	g.stdin, _ = sshSession.StdinPipe()
	go io.Copy(g.stdin, os.Stdin)

	g.stdout, _ = sshSession.StdoutPipe()

	g.stderr, err = sshSession.StderrPipe()
	if err != nil {
		return fmt.Errorf("Unable to setup stderr for session: %v", err)
	}
	go io.Copy(os.Stderr, g.stderr)
	g.echo = false
	// We might need to set this higher for some devices
	if g.timeout == 0 {
		if strings.Contains(g.Model, "3850") {
			g.timeout = 60
		} else {
			g.timeout = 90
		}
	}
	err = sshSession.Shell()
	g.input = make(chan *string)
	g.stop = make(chan struct{})
	g.session = sshSession
	// This is here because of gets rid of
	// the --More-- "prompt" for read-outs
	if g.Vendor == "Cisco" || g.Vendor == "Dell" {
		g.stdin.Write([]byte("terminal length 0\n"))
	}
	return nil
}

// Close the connection to the Device
func (g *Gonet) Close() {
	if g.client != nil {
		g.client.Conn.Close()
	}
	if g.session != nil {
		g.session.Close()
	}
}

// SendCmd to a Device (sh ip int b)
func (g *Gonet) SendCmd(cmd string) (string, error) {
	output := ""
	out, err := g.exec(cmd)
	if err != nil {
		return output, err
	}
	output += out
	outputLines := strings.Split(output, "\n")
	if len(outputLines) == 2 {
		output = ""
	} else if len(outputLines) >= 2 {
		var startIdx int = 1
		if outputLines[0] == "" {
			startIdx = 2
		}
		outputLines = outputLines[startIdx : len(outputLines)-1]
		output = strings.Join(outputLines, "\n")
	}
	return output, nil
}

func (g *Gonet) exec(cmd string) (string, error) {
	var result string
	bufOutput := bufio.NewReader(g.stdout)
	g.stdin.Write([]byte(cmd + "\n"))
	// Pause the thread while the Reader prepares
	// to rcv from the Writer
	delay := 4 * time.Second
	time.Sleep(delay)
	go g.read(bufOutput)
	for {
		select {
		case output := <-g.input:
			switch {
			case output == nil:
				continue
			case !g.echo:
				result = *output
				termLenRe := regexp.MustCompile(`term\slen\s\d|terminal\slength\s\d`)
				termLenIdx := termLenRe.FindIndex([]byte(result))
				if len(termLenIdx) > 0 {
					result = result[termLenIdx[1]+1:]
				}
			default:
				result = *output
			}
			return result, nil
		case <-g.stop:
			g.Close()
			return "", fmt.Errorf("EOF")
		case <-time.After(time.Second * time.Duration(g.timeout)):
			fmt.Println("timeout on", g.IP)
			g.Close()
			return "", fmt.Errorf("timeout")
		}
	}
}

func (g *Gonet) read(r io.Reader) {
	// Setup how to find the Prompt in order
	// Pass Data to our Input Channel
	regex := "[[:alnum:]]>.?$|[[:alnum:]]#.?$|[[:alnum:]]\\$.?$"
	re := regexp.MustCompile(regex)
	if g.prompt != "" {
		re = regexp.MustCompile(g.prompt + ".*?#.?$")
	}
	buf := make([]byte, 1000)
	var input string
	// Read Data into the Buffer until All Data is Passed
	for {
		n, err := r.Read(buf)
		if err != nil {
			if err.Error() != "EOF" {
				fmt.Println("ERROR", err)
			}
			g.stop <- struct{}{}
		}
		input += string(buf[:n])
		if g.Vendor == "Aruba" && strings.Contains(string(buf[:n]), "Password") {
			fmt.Println("**enter enable**")
			g.stdin.Write([]byte(g.Enable + "\n"))
			break
		}
		if g.Vendor == "Aruba" && input[len(input)-1:] == "#" {
			break
		}
		if g.Vendor != "Aruba" && (len(input) >= 50 && re.MatchString(input[len(input)-45:])) ||
			(len(input) < 50 && re.MatchString(input)) {
			break
		}
		// KEEPALIVE
		g.input <- nil
	}
	input = strings.Replace(input, "\r", "", -1)
	g.input <- &input
}
