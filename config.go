package main

import (
	"flag"
	"os"
	"time"
)

type Config struct {
	ListenAddr     string
	StatusAddr     string
	ScrapeURL      string
	ScrapeInterval time.Duration
	CheckTimeout   time.Duration
	MaxConcurrent  int
}

func ParseConfig() *Config {
	cfg := &Config{}
	flag.StringVar(&cfg.ListenAddr, "listen", "127.0.0.1:1080", "local SOCKS5 listen address")
	flag.StringVar(&cfg.StatusAddr, "status", "127.0.0.1:8080", "HTTP status dashboard address")
	flag.StringVar(&cfg.ScrapeURL, "url", "https://socks5-proxy.github.io/", "proxy list URL")
	flag.DurationVar(&cfg.ScrapeInterval, "scrape-interval", 20*time.Minute, "scrape interval")
	flag.DurationVar(&cfg.CheckTimeout, "check-timeout", 15*time.Second, "proxy check timeout")
	flag.IntVar(&cfg.MaxConcurrent, "max-concurrent", 150, "max concurrent health checks")
	flag.Parse()

	// Cloud deployment: always use fixed ports
	// SOCKS5 on 1080, status on given PORT
	if port := os.Getenv("PORT"); port != "" {
		cfg.ListenAddr = "0.0.0.0:1080"
		cfg.StatusAddr = "0.0.0.0:" + port
	}

	return cfg
}
