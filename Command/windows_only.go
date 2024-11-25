//go:build windows
// +build windows

package Command

import (
	"GO_Stager/util"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/saintfish/chardet"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

func cross_platform_exec(cmd string) (string, error) {
	// final_cmd := util.Sprintf("cmd.exe /C %s", cmd)
	// log.Println(final_cmd)
	newProcess := exec.Command("cmd.exe", "/C", cmd)
	// 设置 SysProcAttr.CreationFlags 为 0x08000000（CREATE_NO_WINDOW）避免弹出黑色窗口。
	// 注意：这里直接使用了 CREATE_NO_WINDOW 的数值。
	newProcess.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	output, err := newProcess.CombinedOutput()
	return string(Auto_decode_string_on_windows(output)), err
}

func Auto_decode_string_on_windows(input []byte) (output []byte) {
	// Detect encoding
	detector := chardet.NewTextDetector()
	result, err := detector.DetectBest(input)
	if err != nil {
		log.Println("Error detecting encoding:", err)
		os.Exit(1)
	} else {
		util.Sprintf("\nfound encoding:\t%s\n", result.Charset)
	}

	// Create a decoder for the detected encoding
	var decoder transform.Transformer
	switch strings.ToLower(result.Charset) {
	case "windows-1252", "iso-8859-1":
		decoder = charmap.Windows1252.NewDecoder()
	case "gb-18030":
		//decoder = charmap.GB18030.NewDecoder()
		decoder = simplifiedchinese.GB18030.NewDecoder()
	// Add more cases for other encodings as needed
	case "utf-8":
		decoder = charmap.Windows1252.NewDecoder()

	default:
		msg := util.Sprintf("Unsupported encoding:[%s]", result.Charset)
		return []byte(msg)
	}

	unknownencoding_Output, _, err := transform.Bytes(decoder, input)

	if err != nil {
		util.Println("Error converting to UTF-8:", err)
		os.Exit(1)
	}
	output = unknownencoding_Output
	return output
}
