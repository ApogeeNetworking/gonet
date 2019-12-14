package gonet

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Gonet Main Object
type Gonet struct {
	Username  string
	Password  string
	IP        string
	Echo      bool
	Prompt    string // Finds the Prompt # >
	InputChan chan *string
	StopChan  chan struct{}
	Timeout   int
	Model     string // 9500, 2960, N-Class
	client    *ssh.Client
	session   *ssh.Session
	stdin     io.WriteCloser
	stdout    io.Reader
}

// Connect to the Device with Retries
func (g *Gonet) Connect(retries int) error {
	sshConf := &ssh.ClientConfig{
		Timeout: time.Second * 5,
		User:    g.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(g.Password),
			ssh.KeyboardInteractive(func(user, instr string,
				questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = g.Password
				}
				return answers, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	// Some models of devices may not have the correct ciphers
	// We could handle that hear

	sshClient, err := ssh.Dial("tcp", g.IP+":22", sshConf)
	if err != nil {
		if retries == 0 {
			return nil
		}
		// Before we give up on a filed handshake
		if strings.Contains(err.Error(), "handshake") {
			count := retries - 1
			return g.Connect(count)
		}
		return err
	}
	sshSession, err := sshClient.NewSession()
	if err != nil {
		sshClient.Conn.Close()
		return err
	}
	g.client = sshClient
	g.stdin, _ = sshSession.StdinPipe()
	g.stdout, _ = sshSession.StdoutPipe()
	g.Echo = false
	// We might need to set this higher for some devices
	if g.Timeout == 0 {
		g.Timeout = 45
	}
	sshSession.Shell()
	g.InputChan = make(chan *string, 10)
	g.StopChan = make(chan struct{})
	g.session = sshSession
	// This is here because of gets rid of
	// the --More-- "prompt" for read-outs
	g.stdin.Write([]byte("terminal len 0\n"))
	return nil
}

// Close the connection to the Device
func (g *Gonet) Close() {
	g.client.Conn.Close()
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
	outputLines = outputLines[1 : len(outputLines)-1]
	output = strings.Join(outputLines, "\n")
	return output, nil
}

func (g *Gonet) exec(cmd string) (string, error) {
	var result string
	bufOutput := bufio.NewReader(g.stdout)

	g.stdin.Write([]byte(cmd + "\n"))
	// Pause the thread while the Reader prepares
	// to rcv from the Writer
	time.Sleep(1 * time.Second)

	go g.readln(bufOutput)

	for {
		select {
		case output := <-g.InputChan:
			{
				if output == nil {
					continue
				}
				if g.Echo == false {
					result = *output
					cmdRe := regexp.MustCompile(cmd)
					cmdIdx := cmdRe.FindIndex([]byte(result))
					if len(cmdIdx) == 2 {
						result = result[cmdIdx[1]+1:]
					}
				} else {
					result = *output
				}
				return result, nil
			}
		case <-g.StopChan:
			{
				g.Close()
				return "", fmt.Errorf("EOF")
			}
		case <-time.After(time.Second * time.Duration(g.Timeout)):
			{
				fmt.Println("timeout on", g.IP)
				g.Close()
				return "", fmt.Errorf("timeout")
			}
		}
	}
}

func (g *Gonet) readln(r io.Reader) {
	var re *regexp.Regexp
	// Setup how to find the Prompt in order
	// Pass Data to our Input Channel
	if g.Prompt == "" {
		regex := "[[:alnum:]]>.?$|[[:alnum:]]#.?$|[[:alnum:]]\\$.?$"
		re = regexp.MustCompile(regex)
	} else {
		re = regexp.MustCompile(g.Prompt + ".*?#.?$")
	}
	buf := make([]byte, 10000)
	input := ""
	// Read Data into the Buffer until All Data is Passed
	for {
		n, err := r.Read(buf)
		if err != nil {
			if err.Error() != "EOF" {
				fmt.Println("ERROR", err)
			}
			g.StopChan <- struct{}{}
		}
		input += string(buf[:n])
		if len(input) >= 50 && re.MatchString(input[len(input)-45:]) {
			break
		}
		if len(input) < 50 && re.MatchString(input) {
			break
		}
		// KEEPALIVE
		g.InputChan <- nil
	}
	input = strings.Replace(input, "\r", "", -1)
	g.InputChan <- &input
}
