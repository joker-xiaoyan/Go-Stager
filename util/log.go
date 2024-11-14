package util

import (
	"GO_Stager/config"
	"fmt"
)

func Print(a ...interface{}) {
	if config.Debug {
		fmt.Print(a...)
	}
}

func Printf(format string, a ...interface{}) {
	if config.Debug {
		fmt.Printf(format, a...)
	}
}

func Println(a ...interface{}) {
	if config.Debug {
		fmt.Println(a...)
	}
}

func Errorf(format string, a ...interface{}) error {
	return fmt.Errorf(format, a...)
}

func Sprintf(format string, a ...interface{}) string {
	return fmt.Sprintf(format, a...)
}
