package sysinfo

import (
	"GO_Stager/util"
	"math/rand"
	"net"
	"os"
	"os/user"
	"runtime"
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
	interfaces, err := net.Interfaces()
	if err != nil {
		util.Println("Error retrieving network interfaces:", err)
		return "Unable to determine local IP address"
	}

	for _, iface := range interfaces {
		// 检查接口是否启用且不是回环接口
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			addrs, err := iface.Addrs()
			if err != nil {
				util.Println("Error retrieving addresses for interface:", iface.Name, err)
				continue
			}

			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}

				// 只获取IPv4地址
				if ip != nil && ip.To4() != nil {
					return ip.String()
				}
			}
		}
	}

	return "no ip"
}

func GetIntegrity() string {
	currentUser, err := user.Current()
	if err != nil {
		util.Println("Error retrieving current user:", err)
		return "MEDIUM"
	}

	// 检查当前用户是否为 root
	if currentUser.Username == "root" {
		return "HIGH"
	}

	return "MEDIUM"
}

func GetProcInfo() (int, string) {
	pid := os.Getpid()

	// 获取当前进程名称
	exePath, err := os.Executable()
	if err != nil {
		util.Printf("Error retrieving executable path: %v\n", err)
		return pid, ""
	}

	// 获取可执行文件的名称
	procName := getNameFromPath(exePath)

	return pid, procName
}
func getNameFromPath(path string) string {
	// 提取路径中的文件名部分
	parts := strings.Split(path, string(os.PathSeparator))
	return parts[len(parts)-1]
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
