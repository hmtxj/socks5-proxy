package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// Blocked countries: China mainland + Hong Kong (can't access Google)
var blockedCountries = map[string]bool{
	"china":     true,
	"hong kong": true,
}

func CheckProxies(proxies []Proxy, timeout time.Duration, maxConcurrent int) []Proxy {
	var (
		mu    sync.Mutex
		alive []Proxy
		wg    sync.WaitGroup
		sem   = make(chan struct{}, maxConcurrent)
	)

	host, port := getTestTarget()

	for _, p := range proxies {
		wg.Add(1)
		sem <- struct{}{}
		go func(px Proxy) {
			defer wg.Done()
			defer func() { <-sem }()

			// Lookup geo first, skip blocked countries
			country, city := LookupGeo(px.IP, timeout)
			px.Country = strings.TrimSpace(country)
			px.City = strings.TrimSpace(city)

			if blockedCountries[strings.ToLower(px.Country)] {
				// log.Printf("[checker] %s skipped (%s)", px.Addr(), px.Country)
				return
			}

			if checkTarget(px, host, port, timeout) {
				log.Printf("[checker] %s OK (%s %s)", px.Addr(), px.Country, px.City)
				mu.Lock()
				alive = append(alive, px)
				mu.Unlock()
			}
		}(p)
	}

	wg.Wait()
	log.Printf("[checker] %d/%d proxies alive (Verified %s:%d, non-CN/HK)", len(alive), len(proxies), host, port)
	return alive
}

// checkTarget 通过 SOCKS5 代理连接到目标，验证连通性（443 端口额外验证 TLS 握手）。
func checkTarget(p Proxy, target string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", p.Addr(), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// SOCKS5 握手
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || buf[0] != 0x05 {
		return false
	}

	// 通过 SOCKS5 代理发起 CONNECT 请求
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(target))}
	req = append(req, []byte(target)...)
	req = append(req, byte(port>>8), byte(port&0xff))

	if _, err := conn.Write(req); err != nil {
		return false
	}

	// 【关键修复】精确读取 SOCKS5 CONNECT 响应头（4 字节：VER + REP + RSV + ATYP）
	// 不能用大 buffer 的 conn.Read，否则会多读后续 TLS 数据，导致 TLS 握手失败
	respHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		log.Printf("[checker] %s SOCKS5 响应头读取失败: %v", p.Addr(), err)
		return false
	}
	if respHeader[1] != 0x00 {
		log.Printf("[checker] %s SOCKS5 CONNECT 被拒绝, status=%d", p.Addr(), respHeader[1])
		return false
	}

	// 根据 ATYP 精确读取剩余的绑定地址+端口，确保不多读一个字节
	var remaining int
	switch respHeader[3] {
	case 0x01: // IPv4: 4 字节地址 + 2 字节端口
		remaining = 4 + 2
	case 0x03: // 域名: 1 字节长度 + N 字节域名 + 2 字节端口（先读长度）
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return false
		}
		remaining = int(lenBuf[0]) + 2
	case 0x04: // IPv6: 16 字节地址 + 2 字节端口
		remaining = 16 + 2
	default:
		remaining = 6 // 兜底按 IPv4 处理
	}
	drain := make([]byte, remaining)
	if _, err := io.ReadFull(conn, drain); err != nil {
		return false
	}

	// SOCKS5 隧道建立成功，底层 conn 现在干净地指向目标服务器的数据流
	// 端口 443 时，强制进行 TLS 握手验证
	if port == 443 {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         target,
			InsecureSkipVerify: true, // 只关心能否完成握手
		})
		err = tlsConn.Handshake()
		if err != nil {
			log.Printf("[checker] %s TLS 握手失败: %v", p.Addr(), err)
			// 注意：不调用 tlsConn.Close()，让 defer conn.Close() 统一清理
			return false
		}
		return true
	}

	// 非 443 端口：发送简单的 HTTP HEAD 验证
	httpReq := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	if _, err := conn.Write([]byte(httpReq)); err != nil {
		return false
	}

	respBuf := make([]byte, 512)
	n, err := conn.Read(respBuf)
	if err != nil || n < 4 {
		return false
	}

	return string(respBuf[:4]) == "HTTP"
}

// LookupGeo queries ip-api.com for IP geolocation.
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
