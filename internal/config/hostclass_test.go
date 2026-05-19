package config

import "testing"

func TestIsLoopbackOrDevHost(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"http://localhost", true},
		{"http://localhost:8888", true},
		{"http://127.0.0.1:8080", true},
		{"http://127.0.0.53", true},
		{"http://[::1]:8080", true},
		{"https://wp.docker.localhost", true},
		{"https://foo.test", true},
		{"https://bar.local", true},
		{"http://x.wip", true},
		{"https://y.ddev.site", true},
		{"https://example.com", false},
		{"http://0.0.0.0:8080", false},
		{"notlocal", false},
		{"", false},
		{"://bad", false},
		{"HTTP://LOCALHOST", true},
		{"https://mytest", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsLoopbackOrDevHost(tt.input)
			if got != tt.expected {
				t.Errorf("IsLoopbackOrDevHost(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestHostOf(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://localhost", "localhost"},
		{"http://localhost:8888", "localhost"},
		{"https://WP.Docker.Localhost/path", "wp.docker.localhost"},
		{"http://127.0.0.1:8080", "127.0.0.1"},
		{"://bad", ""},
		{"not-a-url", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := HostOf(tt.input)
			if got != tt.expected {
				t.Errorf("HostOf(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
