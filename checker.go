package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// 中国大陆和香港的代理无法访问目标站，直接跳过
var blockedCountries = map[string]bool{
	"china":     true,
	"hong kong": true,
}

// CheckProxies 并发测试代理列表，返回能访问目标 URL 的存活代理。
func CheckProxies(proxies []Proxy, timeout time.Duration, maxConcurrent int) []Proxy {
	var (
		mu    sync.Mutex
		alive []Proxy
		wg    sync.WaitGroup
		sem   = make(chan struct{}, maxConcurrent)
	)

	targetURL := getTestTargetURL()

	for _, p := range proxies {
		wg.Add(1)
		sem <- struct{}{}
		go func(px Proxy) {
			defer wg.Done()
			defer func() { <-sem }()

			// 先查 IP 归属地，跳过被封锁的地区
			country, city := LookupGeo(px.IP, timeout)
			px.Country = strings.TrimSpace(country)
			px.City = strings.TrimSpace(city)

			if blockedCountries[strings.ToLower(px.Country)] {
				return
			}

			// 通过代理发 HTTP GET 请求到目标 URL（参考 NekoBox 测速逻辑）
			latency, err := httpGetViaProxy(px, targetURL, timeout)
			if err == nil {
				log.Printf("[checker] %s OK %dms (%s %s)", px.Addr(), latency, px.Country, px.City)
				mu.Lock()
				alive = append(alive, px)
				mu.Unlock()
			}
		}(p)
	}

	wg.Wait()
	log.Printf("[checker] %d/%d proxies alive (URL: %s)", len(alive), len(proxies), targetURL)
	return alive
}

// httpGetViaProxy 通过 SOCKS5 代理发起 HTTP GET 请求，返回延迟（毫秒）。
// 参考 NekoBox (libneko/speedtest) 的测速方式：用标准 http.Client 走代理。
func httpGetViaProxy(p Proxy, targetURL string, timeout time.Duration) (latencyMs int64, err error) {
	proxyURL, _ := url.Parse("socks5://" + p.Addr())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
			TLSHandshakeTimeout: timeout,
		},
		Timeout: timeout,
		// 不跟随重定向（和 NekoBox 一样）
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()

	// 参考 NekoBox RTT 模式：做 2 次请求
	// 第 1 次：建立连接 + TLS 握手（预热）
	// 第 2 次：复用连接，测纯 HTTP RTT
	// 不稳定的节点往往第 2 次会失败
	for i := 0; i < 2; i++ {
		start := time.Now()
		resp, err := client.Get(targetURL)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		// 第 2 次请求的耗时才是真正的 RTT
		if i == 1 {
			latencyMs = time.Since(start).Milliseconds()
		}
	}

	return latencyMs, nil
}

// LookupGeo 查询 IP 归属地
func LookupGeo(ip string, timeout time.Duration) (country, city string) {
	conn, err := net.DialTimeout("tcp", "ip-api.com:80", timeout)
	if err != nil {
		return "Unknown", ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf("GET /csv/%s?fields=country,city HTTP/1.1\r\nHost: ip-api.com\r\nConnection: close\r\n\r\n", ip)
	conn.Write([]byte(req))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return "Unknown", ""
	}

	body := string(buf[:n])
	for i := 0; i < len(body)-3; i++ {
		if body[i:i+4] == "\r\n\r\n" {
			body = body[i+4:]
			break
		}
	}

	for i, c := range body {
		if c == ',' {
			return body[:i], body[i+1:]
		}
	}
	return body, ""
}
