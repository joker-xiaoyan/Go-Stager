package Command

import (
	"GO_Stager/util"
	"bufio"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type ProcInfo struct {
	PID        int
	PPID       int
	C          int
	State      string
	Pgrp       int
	Sessions   int
	TTY_nr     int
	Tpgid      int
	Flags      uint
	Minflt     uint
	Cminflt    uint
	Majflt     uint
	CMajflt    uint
	Utime      uint
	Stime      uint
	Cutime     uint
	Cstime     uint
	Priority   int
	Nice       int
	Numthreads int
	Itrealzero uint
	Starttime  string // 时间戳格式，需要解析
	Vsize      uint64
	Rss        uint
	Rip        uint64
	Flags2     uint
}

func getProcInfo(pid int) (ProcInfo, error) {
	file, err := os.Open(util.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ProcInfo{}, util.Errorf("failed to open stat: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return ProcInfo{}, util.Errorf("failed to read stat")
	}

	fields := strings.Fields(scanner.Text())

	info := ProcInfo{}
	for i, field := range fields[1:24] { // 处理到第24个字段，之后是执行路径和其他环境信息
		switch {
		case i == 0:
			info.PID, _ = strconv.Atoi(fields[0])
		case i <= 18 || i >= 19 && i <= 23:
			info.State = fields[i]
			continue // 这个字段需要特殊处理，因为它包含非数字字符
		default:
			val, err := strconv.ParseInt(field, 10, 64)
			if err != nil {
				return ProcInfo{}, util.Errorf("failed to parse field %d: %v", i, err)
			}
			if val > math.MaxInt || val < math.MinInt {
				return ProcInfo{}, util.Errorf("field %d is out of range: %v", i, val)
			}
			valInt := int(val)
			switch i - 18 {
			case 2:
				info.PPID = valInt
			case 3:
				info.C = valInt
			case 4:
				info.State = string(field[0]) // state字段仅需要第一个字符
			case 5:
				info.Pgrp = valInt
			case 6:
				info.Sessions = valInt
			case 7:
				info.TTY_nr = valInt
			case 8:
				info.Tpgid = valInt
			case 9:
				info.Flags = uint(val)
			case 10:
				info.Minflt = uint(val)
			case 11:
				info.Cminflt = uint(val)
			case 12:
				info.Majflt = uint(val)
			case 13:
				info.CMajflt = uint(val)
			case 14:
				info.Utime = uint(val)
			case 15:
				info.Stime = uint(val)
			case 16:
				info.Cutime = uint(val)
			case 17:
				info.Cstime = uint(val)
			case 18:
				info.Priority = valInt
			case 19:
				info.Nice = int(val)
			case 20:
				info.Numthreads = int(val)
			case 21:
				info.Itrealzero = uint(val)
			case 22:
				info.Starttime = field
			case 23:
				val, err := strconv.ParseUint(field, 10, 64)
				if err != nil {
					return ProcInfo{}, util.Errorf("failed to parse Vsize: %v", err)
				}
				info.Vsize = uint64(val)
			}
		}

		return info, nil
	}
	return ProcInfo{}, util.Errorf("failed to get proc info")
}

func readCmdLine(pid int) string {
	file, _ := os.Open(util.Sprintf("/proc/%d/cmdline", pid))
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		return strings.Replace(scanner.Text(), "\x00", " ", -1)
	}

	return ""
}

func ps() (string, error) {
	procDir := "/proc"
	entries, _ := os.ReadDir(procDir)
	var result strings.Builder
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err == nil && entry.IsDir() { // Check if it's a valid number and a directory
			info, err := getProcInfo(pid)
			if err != nil {
				continue
			}
			if readCmdLine(pid) != "" {
				result.WriteString("Pid: " + strconv.Itoa(info.PID) + " Cmdline: " + readCmdLine(pid) + "\n")
			}
		}
	}
	return result.String(), nil
}

func getAbsolutePath(filePath string) (string, error) {
	util.Println(filePath + "   111")
	if filepath.IsAbs(filePath) { // 如果是绝对路径直接返回
		return filePath, nil
	}
	dir, err := os.Getwd() // 获取当前工作目录作为起点
	if err != nil {
		return "", err
	}
	absolutePath := filepath.Join(dir, filePath) // 将相对路径转换为绝对路径
	return absolutePath, nil
}
