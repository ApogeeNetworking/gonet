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
	Port     string
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

func (g *Gonet) keyInter(u, in string, q []string, e []bool) ([]string, error) {
	// Just send the password back for all questions
	answers := make([]string, len(q))
	for i := range answers {
		answers[i] = g.Password
	}

	return answers, nil
}

// Connect to the Device with Retries
func (g *Gonet) Connect(retries int) error {
	sshConf := &ssh.ClientConfig{
		User: g.Username,
		Auth: []ssh.AuthMethod{
			ssh.KeyboardInteractive(g.keyInter),
			ssh.Password(g.Password),
			ssh.PasswordCallback(g.getPass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         12 * time.Second,
	}
	sshConf.SetDefaults()
	sshConf.Ciphers = append(sshConf.Ciphers, "aes128-cbc")
	sshConf.KeyExchanges = append(sshConf.KeyExchanges, "diffie-hellman-group-exchange-sha1")
	sshConf.KeyExchanges = append(sshConf.KeyExchanges, "diffie-hellman-group1-sha1")
	// Some models of devices may not have the correct ciphers
	// We could handle that hear
	if g.Port == "" {
		g.Port = "22"
	}
	sshClient, err := ssh.Dial("tcp", g.IP+":"+g.Port, sshConf)
	if err != nil {
		// Before we give up on a failed handshake
		if strings.Contains(err.Error(), "handshake") {
			count := retries - 1
			if count == 0 {
				return err
			}
			return g.Connect(count)
		}
		return err
	}
	g.client = sshClient
	sshSession, err := g.client.NewSession()
	if err != nil {
		sshClient.Conn.Close()
		return err
	}
	g.session = sshSession
	modes := ssh.TerminalModes{
		ssh.ECHO:          0, // disable echoing
		ssh.OCRNL:         0,
		ssh.TTY_OP_ISPEED: 38400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 38400, // output speed = 14.4kbaud
	}

	if err := g.session.RequestPty("xterm", 0, 5000, modes); err != nil {
		g.session.Close()
		return fmt.Errorf("request for pseudo terminal failed: %s", err)
	}
	g.stdin, _ = g.session.StdinPipe()
	go io.Copy(g.stdin, os.Stdin)

	g.stdout, _ = g.session.StdoutPipe()

	g.stderr, err = g.session.StderrPipe()
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
			g.timeout = 500
		}
	}
	err = g.session.Shell()
	// This is here because of gets rid of
	// the --More-- "prompt" for read-outs
	if g.Vendor == "Cisco" || g.Vendor == "Dell" || g.Model == "N1548P" {
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

// NcSend ...
func (g *Gonet) NcSend(data []byte) string {
	g.session.RequestSubsystem("netconf")
	g.stdin.Write(data)
	time.Sleep(100 * time.Millisecond)
	return ""
}

// SendConfig ...
func (g *Gonet) SendConfig(cmd string) {
	g.stdin.Write([]byte(cmd + "\n"))
	time.Sleep(100 * time.Millisecond)
}

// ExecEnable ...
func (g *Gonet) ExecEnable() {
	g.stdin.Write([]byte("enable\n"))
	time.Sleep(100 * time.Millisecond)
	g.stdin.Write([]byte(g.Enable + "\n"))
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

// SendRawCmd used to receive complete output from CMD
// Helps to determine exactly what the Prompt of the Device is
func (g *Gonet) SendRawCmd(c string) string {
	var output string
	out, _ := g.exec(c)
	output += out
	return output
}

func (g *Gonet) exec(cmd string) (string, error) {
	var result string
	input := make(chan *string)
	stop := make(chan struct{})

	bufOutput := bufio.NewReader(g.stdout)
	g.stdin.Write([]byte(cmd + "\n"))
	// Pause the thread while the Reader prepares
	// to rcv from the Writer
	delay := 1 * time.Second
	if strings.Contains(g.Vendor, "Dell") || g.Model == "N1548P" {
		delay = 4 * time.Second
	}
	time.Sleep(delay)
	go g.read(bufOutput, input, stop)
	for {
		select {
		case output := <-input:
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
		case <-stop:
			fmt.Println(<-stop)
			g.Close()
			return "", fmt.Errorf("EOF")
		case <-time.After(time.Second * time.Duration(g.timeout)):
			fmt.Println("timeout on", g.IP)
			g.Close()
			return "", fmt.Errorf("timeout")
		}
	}
}

func (g *Gonet) read(r *bufio.Reader, in chan *string, stop chan struct{}) {
	// Setup how to find the Prompt in order
	// Pass Data to our Input Channel

	// regex := "[[:alnum:]](?:#|>)$"
	// if g.Vendor == "Cisco" {
	regex := "[[:alnum:]]>.?$|[[:alnum:]]#.?$|[[:alnum:]]\\$.?$"
	// }
	re := regexp.MustCompile(regex)
	if g.prompt != "" {
		re = regexp.MustCompile(g.prompt + ".*?#.?$")
	}
	buf := make([]byte, 204800000)
	var input string
	// Read Data into the Buffer until All Data is Passed
	for {
		n, err := r.Read(buf)
		if err != nil {
			if err.Error() != "EOF" {
				fmt.Println("ERROR", err)
			}
			stop <- struct{}{}
		}
		input += string(buf[:n])
		if (len(input) >= 50 && re.MatchString(input[len(input)-45:])) ||
			(len(input) < 50 && re.MatchString(input)) {
			break
		}
		// KEEPALIVE
		in <- nil
	}
	input = strings.Replace(input, "\r", "", -1)
	in <- &input
}
