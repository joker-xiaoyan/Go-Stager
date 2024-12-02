@echo off


REM 构建 Windows 64-bit 版本
echo Building for Windows (amd64)
set GOOS=windows
set GOARCH=amd64

go build -ldflags="-s -w" -o hger_windows.exe

REM 构建 Linux 64-bit 版本
echo Building for Linux (amd64)
set GOOS=linux
set GOARCH=amd64

go build -ldflags="-s -w" -o hger_linux

@REM REM 构建 Linux arm64 版本
@REM echo Building for Linux (arm64)
@REM set GOOS=linux
@REM set GOARCH=arm64

@REM go build -ldflags="-s -w" -o hger_linux_arm64
@REM REM 构建 macOS (Darwin) 64-bit 版本
@REM echo Building for macOS (darwin)
@REM set GOOS=darwin
@REM set GOARCH=amd64
@REM go build -o %PROJECT_DIR%\hello_darwin_amd64 .
@REM if errorlevel 1 (
@REM     echo Error building macOS (darwin) version.
@REM     exit /b 1
@REM )

@REM REM 构建 Windows 32-bit 版本
@REM echo Building for Windows (386)
@REM set GOOS=windows
@REM set GOARCH=386
@REM go build -o %PROJECT_DIR%\hello_386.exe .
@REM if errorlevel 1 (
@REM     echo Error building Windows (386) version.
@REM     exit /b 1
@REM )

@REM REM 构建 Linux 32-bit 版本
@REM echo Building for Linux (386)
@REM set GOOS=linux
@REM set GOARCH=386
@REM go build -o %PROJECT_DIR%\hello_linux_386 .
@REM if errorlevel 1 (
@REM     echo Error building Linux (386) version.
@REM     exit /b 1
@REM )

@REM REM 构建 macOS (Darwin) 32-bit 版本
@REM echo Building for macOS (darwin, 386)
@REM set GOOS=darwin
@REM set GOARCH=386
@REM go build -o %PROJECT_DIR%\hello_darwin_386 .
@REM if errorlevel 1 (
@REM     echo Error building macOS (darwin, 386) version.
@REM     exit /b 1
@REM )

echo All builds complete.
exit /b 0