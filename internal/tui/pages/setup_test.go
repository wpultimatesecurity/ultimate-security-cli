package pages

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/messages"
)

func TestSetupPageHTTPWarning(t *testing.T) {
	t.Run("http localhost shows muted hint", func(t *testing.T) {
		p := &SetupPage{siteURL: "http://localhost:8888"}
		w := p.httpWarning()
		if w == "" {
			t.Fatal("expected warning for http localhost")
		}
	})

	t.Run("http example.com shows red warning", func(t *testing.T) {
		p := &SetupPage{siteURL: "http://example.com"}
		w := p.httpWarning()
		if w == "" {
			t.Fatal("expected warning for http example.com")
		}
	})

	t.Run("https example.com shows nothing", func(t *testing.T) {
		p := &SetupPage{siteURL: "https://example.com"}
		w := p.httpWarning()
		if w != "" {
			t.Errorf("expected no warning for https, got %q", w)
		}
	})

	t.Run("http wp.docker.localhost shows muted hint", func(t *testing.T) {
		p := &SetupPage{siteURL: "http://wp.docker.localhost"}
		w := p.httpWarning()
		if w == "" {
			t.Fatal("expected warning for http wp.docker.localhost")
		}
	})
}

func TestSetupPageView(t *testing.T) {
	t.Run("View renders without crash", func(t *testing.T) {
		p := NewSetupPage()
		p.Init()
		v := p.View()
		if v.Content == "" {
			t.Error("expected non-empty view")
		}
	})
}

func TestSetupPageTestConnection(t *testing.T) {
	t.Run("empty fields return error", func(t *testing.T) {
		p := NewSetupPage()
		cmd := p.testConnection()
		msg := cmd()
		ccm, ok := msg.(messages.ConnectionChangedMsg)
		if !ok {
			t.Fatalf("expected ConnectionChangedMsg, got %T", msg)
		}
		if ccm.Connected {
			t.Error("expected not connected")
		}
		if ccm.Err == nil {
			t.Error("expected error for empty fields")
		}
	})

	t.Run("/wp-admin URL rejected", func(t *testing.T) {
		p := NewSetupPage()
		p.siteURL = "https://example.com/wp-admin"
		p.username = "admin"
		p.appPassword = "xxxx"
		cmd := p.testConnection()
		msg := cmd()
		ccm, ok := msg.(messages.ConnectionChangedMsg)
		if !ok {
			t.Fatalf("expected ConnectionChangedMsg, got %T", msg)
		}
		if ccm.Connected {
			t.Error("expected not connected")
		}
		if ccm.Err == nil {
			t.Error("expected error for /wp-admin URL")
		}
	})
}

func TestSetupPageWithTLSServer(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"version":"1.0.19","plugin_active":true}}`))
	}))
	defer server.Close()

	p := NewSetupPage()
	p.siteURL = server.URL
	p.username = "admin"
	p.appPassword = "xxxx"
	p.verifySSL = false

	cmd := p.testConnection()
	msg := cmd()

	ccm, ok := msg.(messages.ConnectionChangedMsg)
	if !ok {
		t.Fatalf("expected ConnectionChangedMsg, got %T", msg)
	}
	if !ccm.Connected {
		t.Errorf("expected connected, got error: %v", ccm.Err)
	}
}
