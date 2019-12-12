package main

import (
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/drkchiloll/gonet"
	"github.com/subosito/gotenv"
)

var wg sync.WaitGroup

// NetDevice is an arbitrary struct representing our Device
type NetDevice struct {
	Vendor string // dell, cisco, et al
	Model  string // ex. 9500 (for Cisco 9500)
	IP     string // IP Addr or Hostname
}

func init() {
	gotenv.Load()
}

func getClient(cfg NetDevice) *gonet.Gonet {
	username := os.Getenv("SSH_USER")
	password := os.Getenv("SSH_PW")
	// Gonet is the main Object for our ConnectionHandling
	// And CLI Processing
	return &gonet.Gonet{
		IP:       cfg.IP,
		Username: username,
		Password: password,
		Model:    cfg.Model,
	}
}

func oneDevice() {
	device := NetDevice{
		IP:     "xx.xx.xx.xx",
		Vendor: "cisco",
		Model:  "9500",
	}
	gclient := getClient(device)

	// Connect to the Device
	err := gclient.Connect(3)
	if err != nil {
		log.Print(err)
	}
	defer gclient.Close()

	cmds := []string{
		"show ip int b twe1/0/1",
		"show ip int b twe1/0/2",
	}
	var output []string
	for _, cmd := range cmds {
		out, _ := gclient.SendCmd(cmd)
		output = append(output, out)
	}
	if err != nil {
		log.Println(err)
	}
	fmt.Println(output)
}

func manyDevices() {}

func main() {
	oneDevice()
}
