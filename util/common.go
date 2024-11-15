package util

import (
	"encoding/json"
	"strings"
)

type Params struct {
	OptionName  string `json:"OptionName"`
	OptionValue string `json:"OptionValue"`
}

type ArgsStruct struct {
	Params []Params `json:"Params"`
}

func Strim(args string) (string, error) {
	var cmdArgs ArgsStruct
	err := json.Unmarshal([]byte(strings.ReplaceAll(strings.ReplaceAll(args, `\"`, `"`), `\\`, `\`)), &cmdArgs)
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
	return cmdstr, nil
}
