package config

import (
	"net"
	"net/url"
	"strings"
)

var devTLDs = []string{".localhost", ".test", ".local", ".wip", ".ddev.site"}

func HostOf(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func IsLoopbackOrDevHost(rawURL string) bool {
	host := HostOf(rawURL)
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	if host == "localhost" {
		return true
	}
	for _, s := range devTLDs {
		if strings.HasSuffix(host, s) {
			return true
		}
	}
	return false
}
