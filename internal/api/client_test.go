package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/config"
)

func TestClientTLS(t *testing.T) {
	t.Run("default verify fails with self-signed cert", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		site := &config.SiteConfig{
			Name:        "test",
			URL:         server.URL,
			Username:    "admin",
			AppPassword: "xxxx",
		}
		client := NewClient(site, config.DefaultConfig().API)
		_, err := client.Get(context.Background(), "/", nil)
		if err == nil {
			t.Fatal("expected error for untrusted self-signed cert")
		}
		if !IsNetwork(err) {
			t.Fatalf("expected NetworkError, got %T: %v", err, err)
		}
		if !containsHint(err, "ca_cert") {
			t.Errorf("expected ca_cert hint in error: %v", err)
		}
	})

	t.Run("ca_cert trusts server cert", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"success":true}`))
		}))
		defer server.Close()

		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
		certPath := filepath.Join(t.TempDir(), "server.pem")
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			t.Fatal(err)
		}

		site := &config.SiteConfig{
			Name:        "test",
			URL:         server.URL,
			Username:    "admin",
			AppPassword: "xxxx",
			CACert:      certPath,
		}
		client := NewClient(site, config.DefaultConfig().API)
		_, err := client.Get(context.Background(), "/", nil)
		if err != nil {
			t.Fatalf("expected success with ca_cert, got %v", err)
		}
	})

	t.Run("verify_ssl: false succeeds regardless of cert", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"success":true}`))
		}))
		defer server.Close()

		v := false
		site := &config.SiteConfig{
			Name:        "test",
			URL:         server.URL,
			Username:    "admin",
			AppPassword: "xxxx",
			VerifySSL:   &v,
		}
		client := NewClient(site, config.DefaultConfig().API)
		_, err := client.Get(context.Background(), "/", nil)
		if err != nil {
			t.Fatalf("expected success with verify_ssl:false, got %v", err)
		}
	})

	t.Run("verify_ssl: false with bogus ca_cert still succeeds", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"success":true}`))
		}))
		defer server.Close()

		v := false
		site := &config.SiteConfig{
			Name:        "test",
			URL:         server.URL,
			Username:    "admin",
			AppPassword: "xxxx",
			VerifySSL:   &v,
			CACert:      "/nonexistent/ca.pem",
		}
		client := NewClient(site, config.DefaultConfig().API)
		_, err := client.Get(context.Background(), "/", nil)
		if err != nil {
			t.Fatalf("expected success with verify_ssl:false + bogus ca_cert, got %v", err)
		}
	})

	t.Run("401 over http loopback carries WP_ENV hint", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		site := &config.SiteConfig{
			Name:        "test",
			URL:         server.URL,
			Username:    "admin",
			AppPassword: "xxxx",
		}
		client := NewClient(site, config.DefaultConfig().API)
		_, err := client.Get(context.Background(), "/", nil)
		if err == nil {
			t.Fatal("expected auth error")
		}
		if !IsAuth(err) {
			t.Fatalf("expected AuthError, got %T: %v", err, err)
		}
		if !containsHint(err, "WP_ENVIRONMENT_TYPE") {
			t.Errorf("expected WP_ENVIRONMENT_TYPE hint in error: %v", err)
		}
	})

	t.Run("https on http server gives record header hint", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		site := &config.SiteConfig{
			Name:        "test",
			URL:         server.URL,
			Username:    "admin",
			AppPassword: "xxxx",
		}
		b := true
		site.VerifySSL = &b
		client := NewClient(site, config.DefaultConfig().API)
		client.baseURL = "https://localhost" + server.URL[len("http://localhost"):] + "/wp-json/ultimate-security/v1"
		_, err := client.Get(context.Background(), "/", nil)
		if err == nil {
			t.Fatal("expected error")
		}
		if !IsNetwork(err) {
			t.Fatalf("expected NetworkError, got %T: %v", err, err)
		}
		if !containsHint(err, "plain HTTP") {
			t.Errorf("expected plain HTTP hint in error: %v", err)
		}
	})
}

func containsHint(err error, substr string) bool {
	msg := err.Error()
	return len(msg) > 0 && (msg[len(msg)-len(substr):] == substr || contains(msg, substr))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && search(s, substr)
}

func search(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestLoadCACertPool(t *testing.T) {
	t.Run("empty ca_cert returns nil", func(t *testing.T) {
		site := &config.SiteConfig{}
		pool, err := loadCACertPoolTest(site, "")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if pool != nil {
			t.Fatal("expected nil pool for empty ca_cert")
		}
	})

	t.Run("valid cert loads", func(t *testing.T) {
		server := httptest.NewTLSServer(nil)
		defer server.Close()

		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
		certPath := filepath.Join(t.TempDir(), "server.pem")
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			t.Fatal(err)
		}

		site := &config.SiteConfig{CACert: certPath}
		pool, err := loadCACertPoolTest(site, "")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if pool == nil {
			t.Fatal("expected non-nil pool")
		}
	})
}

func loadCACertPoolTest(site *config.SiteConfig, configDir string) (*x509.CertPool, error) {
	path, err := site.ResolveCACertPath(configDir)
	if err != nil || path == "" {
		return nil, err
	}
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, err
	}
	return pool, nil
}
