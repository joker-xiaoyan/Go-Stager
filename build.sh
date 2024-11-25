#!/bin/bash

# 清理旧的输出
rm -rf GO_Stager

# Windows 64-bit
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o GO_Stager.exe .

# Linux 64-bit
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o GO_Stager_linux_amd64 .

# macOS (Darwin) 64-bit
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o GO_Stager_darwin_amd64 .
