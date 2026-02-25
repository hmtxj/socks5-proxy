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

// checkTarget connects through the proxy to target endpoint and verify TLS if port is 443.
func checkTarget(p Proxy, target string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", p.Addr(), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// SOCKS5 greeting
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || buf[0] != 0x05 {
		return false
	}

	// Connect to Target through SOCKS5 proxy
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(target))}
	req = append(req, []byte(target)...)
	req = append(req, byte(port>>8), byte(port&0xff))

	if _, err := conn.Write(req); err != nil {
		return false
	}

	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil || n < 2 || resp[1] != 0x00 {
		return false
	}

	// SOCKS5 relay established successfully.
	// If the port is 443, mandate a full TLS handshake!
	if port == 443 {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         target,
			InsecureSkipVerify: true, // We only care if we can handshake
		})
		err = tlsConn.Handshake()
		tlsConn.Close()
		if err != nil {
			return false // Intercepted or blocked by CDN/Firewall
		}
		return true // TLS Handshake success
	}

	// For non-443 ports, send a simple HEAD request
	httpReq := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	if _, err := conn.Write([]byte(httpReq)); err != nil {
		return false
	}

	respBuf := make([]byte, 512)
	n, err = conn.Read(respBuf)
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
