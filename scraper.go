package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	// 匹配代理地址：支持 "socks5://IP:PORT" 和纯 "IP:PORT" 格式
	proxyRegex = regexp.MustCompile(`(?:socks[45]://)?(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d+)`)

	// 多源代理列表
	defaultSources = []string{
		"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all&ssl=all&anonymity=all",
		"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
		"https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
		"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
		"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
		"https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
		"https://raw.githubusercontent.com/Boster123/Free_Proxy_List/main/socks5.txt",
		"https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt",
	}
)

type Proxy struct {
	IP      string
	Port    string
	Country string
	City    string
}

func (p Proxy) Addr() string {
	return p.IP + ":" + p.Port
}

func (p Proxy) String() string {
	return fmt.Sprintf("socks5://%s:%s", p.IP, p.Port)
}

// buildHTTPClient 根据运行环境创建 HTTP 客户端。
// 云端（Zeabur/Railway）直连；本地环境走 127.0.0.1:7890 翻墙代理。
func buildHTTPClient() *http.Client {
	transport := &http.Transport{}

	if os.Getenv("PORT") == "" {
		// 本地环境：通过 Clash 代理拉取被墙的 GitHub raw
		proxyURL, _ := url.Parse("http://127.0.0.1:7890")
		transport.Proxy = http.ProxyURL(proxyURL)
		log.Printf("[scraper] 本地模式，使用代理 127.0.0.1:7890")
	} else {
		// 云端环境：直连（Zeabur/Railway 服务器不受墙限制）
		log.Printf("[scraper] 云端模式，直连拉取")
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

func Scrape(baseURL string) ([]Proxy, error) {
	var allProxies []Proxy
	seen := make(map[string]bool)
	client := buildHTTPClient()

	for _, sourceUrl := range defaultSources {
		log.Printf("[scraper] Fetching from: %s", sourceUrl)

		req, _ := http.NewRequest("GET", sourceUrl, nil)
		resp, err := client.Do(req)

		if err != nil {
			log.Printf("[scraper] source failed %s: %v", sourceUrl, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		matches := proxyRegex.FindAllStringSubmatch(string(body), -1)
		count := 0
		for _, m := range matches {
			addr := m[1] + ":" + m[2]
			if seen[addr] {
				continue
			}
			seen[addr] = true
			allProxies = append(allProxies, Proxy{
				IP:   strings.TrimSpace(m[1]),
				Port: strings.TrimSpace(m[2]),
			})
			count++
		}
		log.Printf("[scraper] ✅ Extracted %d unique proxies from %s", count, sourceUrl)
	}

	total := len(allProxies)
	if total == 0 {
		return nil, fmt.Errorf("all sources failed or returned 0 proxies")
	}

	log.Printf("[scraper] 🎉 Total extracted raw proxies: %d", total)
	return allProxies, nil
}
