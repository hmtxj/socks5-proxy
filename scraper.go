package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	// 放宽匹配规则，可以匹配带有 "socks5://" 前缀的，也可以直接匹配纯数字的 "192.168.1.1:1080" 格式
	proxyRegex = regexp.MustCompile(`(?:socks[45]://)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)`)
	
	// 高质量全球 SOCKS5 代理源列表
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

func Scrape(baseURL string) ([]Proxy, error) {
	// 忽略传入的单源，直接爬取写死的所有多源列表
	var allProxies []Proxy
	seen := make(map[string]bool)

	// 在 Zeabur/海外服务器无需翻墙，直接直连获取源
	// 移除本地调试专用的 127.0.0.1:7890
	client := &http.Client{
		Transport: &http.Transport{},
		Timeout: 30 * time.Second, // 防止单个源卡死
	}
	
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
		resp.Body.Close() // 及时关闭
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
