package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"time"
)

// 中国大陆和香港的代理无法访问目标站，直接跳过
var blockedCountries = map[string]bool{
	"china":     true,
	"hong kong": true,
}

// NekoBox 原版：重定向视为成功，不算 error
var errNoRedir = errors.New("no redir")

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

			// 通过代理做 NekoBox 原版 UrlTest（RTT 模式）
			latency, err := httpGetViaProxy(px, targetURL, timeout)
			if err == nil {
				px.Latency = latency
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

// dialViaSocks5 通过 SOCKS5 代理建立 TCP 连接（纯标准库，无需 x/net）
func dialViaSocks5(proxyAddr, targetHost string, targetPort int, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))

	// SOCKS5 握手：无认证
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || buf[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("socks5 handshake failed")
	}

	// CONNECT 请求
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(targetHost))}
	req = append(req, []byte(targetHost)...)
	req = append(req, byte(targetPort>>8), byte(targetPort&0xff))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	// 读取响应头
	respHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		conn.Close()
		return nil, err
	}
	if respHeader[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect rejected: %d", respHeader[1])
	}

	// 根据 ATYP 读取剩余地址和端口
	var remaining int
	switch respHeader[3] {
	case 0x01:
		remaining = 4 + 2
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			conn.Close()
			return nil, err
		}
		remaining = int(lenBuf[0]) + 2
	case 0x04:
		remaining = 16 + 2
	default:
		remaining = 6
	}
	drain := make([]byte, remaining)
	if _, err := io.ReadFull(conn, drain); err != nil {
		conn.Close()
		return nil, err
	}

	// 清除 deadline，让上层自行管理
	conn.SetDeadline(time.Time{})
	return conn, nil
}

// httpGetViaProxy 完全照抄 NekoBox speedtest.UrlTest（RTT 模式）。
// 2 次请求：第 1 次建连+TLS 预热，第 2 次复用连接测纯 RTT。
// 延迟 = GotFirstResponseByte 时间 - TLS 握手完成时间（和 NekoBox 一模一样）。
func httpGetViaProxy(p Proxy, targetURL string, timeout time.Duration) (latencyMs int64, err error) {
	client := &http.Client{
		Transport: &http.Transport{
			// 所有 TCP 连接通过 SOCKS5 代理拨号，TLS 由 Transport 自动处理
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, portStr, _ := net.SplitHostPort(addr)
				port := 80
				fmt.Sscanf(portStr, "%d", &port)
				return dialViaSocks5(p.Addr(), host, port, timeout)
			},
			TLSHandshakeTimeout: timeout,
		},
		Timeout: timeout,
		// NekoBox 原版：重定向返回自定义 error，后续 catch 住当作成功
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errNoRedir
		},
	}
	defer client.CloseIdleConnections()

	// NekoBox 原版 httptrace：精确记录 TLS 握手完成时间和首字节到达时间
	var timeStart time.Time
	var hskEnd time.Time
	var timeEnd time.Time

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, reqErr := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if reqErr != nil {
		return 0, reqErr
	}

	trace := &httptrace.ClientTrace{
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			hskEnd = time.Now()
		},
		GotFirstResponseByte: func() {
			timeEnd = time.Now()
		},
		WroteHeaders: func() {
			hskEnd = time.Now()
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	// RTT 模式：做 2 次请求
	for i := 0; i < 2; i++ {
		timeStart = time.Now()
		resp, doErr := client.Do(req)
		if doErr != nil {
			// NekoBox 原版：重定向不算失败
			if errors.Is(doErr, errNoRedir) {
				doErr = nil
			} else {
				return 0, doErr
			}
		}
		resp.Body.Close()
	}

	// NekoBox 原版：如果 GotFirstResponseByte 没触发，用当前时间兜底
	if timeEnd.IsZero() {
		timeEnd = time.Now()
	}

	// RTT 模式：延迟 = 首字节时间 - TLS 握手完成时间
	timeStart = hskEnd
	return int64(timeEnd.Sub(timeStart).Milliseconds()), nil
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
