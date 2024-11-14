package Command

import (
	"GO_Stager/util"
	"os"
	"os/exec"
	"strings"
)

func ShellExecute(command string, args []string) (string, error) {
	sh_path := "/bin/bash"
	_, err := os.Stat(sh_path)
	if err != nil {
		sh_path = "/bin/sh"
	}
	cmd := exec.Command(sh_path, "-c", command+" "+strings.Join(args, " "))
	util.Println(cmd.String())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), err
	}
	return string(output), err
}
