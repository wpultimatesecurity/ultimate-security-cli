package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyEnabled(t *testing.T) {
	t.Run("nil pointer returns true", func(t *testing.T) {
		s := &SiteConfig{}
		if !s.VerifyEnabled() {
			t.Error("expected VerifyEnabled() == true for nil VerifySSL")
		}
	})
	t.Run("false pointer returns false", func(t *testing.T) {
		b := false
		s := &SiteConfig{VerifySSL: &b}
		if s.VerifyEnabled() {
			t.Error("expected VerifyEnabled() == false")
		}
	})
	t.Run("true pointer returns true", func(t *testing.T) {
		b := true
		s := &SiteConfig{VerifySSL: &b}
		if !s.VerifyEnabled() {
			t.Error("expected VerifyEnabled() == true")
		}
	})
}

func TestVerifySSLFromYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	t.Run("omit verify_ssl defaults to true", func(t *testing.T) {
		data := `sites:
  - name: test
    url: https://example.com
    username: admin
    app_password: "xxxx"
`
		if err := os.WriteFile(cfgPath, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.Sites[0].VerifyEnabled() {
			t.Error("expected VerifyEnabled() == true when verify_ssl omitted")
		}
	})

	t.Run("verify_ssl: false", func(t *testing.T) {
		data := `sites:
  - name: test
    url: https://example.com
    username: admin
    app_password: "xxxx"
    verify_ssl: false
`
		if err := os.WriteFile(cfgPath, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Sites[0].VerifyEnabled() {
			t.Error("expected VerifyEnabled() == false")
		}
	})

	t.Run("verify_ssl: true", func(t *testing.T) {
		data := `sites:
  - name: test
    url: https://example.com
    username: admin
    app_password: "xxxx"
    verify_ssl: true
`
		if err := os.WriteFile(cfgPath, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.Sites[0].VerifyEnabled() {
			t.Error("expected VerifyEnabled() == true")
		}
	})
}

func TestEnvOverrideVerifySSL(t *testing.T) {
	t.Run("true", func(t *testing.T) {
		t.Setenv("USCLI_SITE_URL", "https://example.com")
		t.Setenv("USCLI_SITE_USERNAME", "admin")
		t.Setenv("USCLI_SITE_APP_PASSWORD", "xxxx")
		t.Setenv("USCLI_VERIFY_SSL", "true")
		cfg := DefaultConfig()
		applyEnvOverrides(&cfg)
		if !cfg.Sites[0].VerifyEnabled() {
			t.Error("expected VerifyEnabled() == true")
		}
	})
	t.Run("1", func(t *testing.T) {
		t.Setenv("USCLI_SITE_URL", "https://example.com")
		t.Setenv("USCLI_SITE_USERNAME", "admin")
		t.Setenv("USCLI_SITE_APP_PASSWORD", "xxxx")
		t.Setenv("USCLI_VERIFY_SSL", "1")
		cfg := DefaultConfig()
		applyEnvOverrides(&cfg)
		if !cfg.Sites[0].VerifyEnabled() {
			t.Error("expected VerifyEnabled() == true")
		}
	})
	t.Run("false", func(t *testing.T) {
		t.Setenv("USCLI_SITE_URL", "https://example.com")
		t.Setenv("USCLI_SITE_USERNAME", "admin")
		t.Setenv("USCLI_SITE_APP_PASSWORD", "xxxx")
		t.Setenv("USCLI_VERIFY_SSL", "false")
		cfg := DefaultConfig()
		applyEnvOverrides(&cfg)
		if cfg.Sites[0].VerifyEnabled() {
			t.Error("expected VerifyEnabled() == false")
		}
	})
	t.Run("unset falls through", func(t *testing.T) {
		os.Unsetenv("USCLI_VERIFY_SSL")
		cfg := DefaultConfig()
		applyEnvOverrides(&cfg)
		if len(cfg.Sites) > 0 && cfg.Sites[0].VerifySSL != nil {
			t.Error("expected VerifySSL to remain nil when env unset")
		}
	})
}

func TestEnvOverrideCACert(t *testing.T) {
	t.Setenv("USCLI_SITE_URL", "https://example.com")
	t.Setenv("USCLI_SITE_USERNAME", "admin")
	t.Setenv("USCLI_SITE_APP_PASSWORD", "xxxx")
	t.Setenv("USCLI_CA_CERT", "/path/to/ca.pem")
	cfg := DefaultConfig()
	applyEnvOverrides(&cfg)
	if cfg.Sites[0].CACert != "/path/to/ca.pem" {
		t.Errorf("expected CACert = /path/to/ca.pem, got %q", cfg.Sites[0].CACert)
	}
}

func TestResolveCACertPath(t *testing.T) {
	home, _ := os.UserHomeDir()

	t.Run("empty returns empty", func(t *testing.T) {
		s := &SiteConfig{}
		p, err := s.ResolveCACertPath("/cfg")
		if err != nil || p != "" {
			t.Errorf("expected empty, got %q err=%v", p, err)
		}
	})
	t.Run("tilde expands", func(t *testing.T) {
		s := &SiteConfig{CACert: "~/ca.pem"}
		p, err := s.ResolveCACertPath("/cfg")
		if err != nil {
			t.Fatal(err)
		}
		expected := filepath.Join(home, "ca.pem")
		if p != expected {
			t.Errorf("expected %q, got %q", expected, p)
		}
	})
	t.Run("relative resolves against configDir", func(t *testing.T) {
		s := &SiteConfig{CACert: "ca.pem"}
		p, err := s.ResolveCACertPath("/cfg")
		if err != nil {
			t.Fatal(err)
		}
		expected := filepath.Clean("/cfg/ca.pem")
		if p != expected {
			t.Errorf("expected %q, got %q", expected, p)
		}
	})
	t.Run("absolute unchanged", func(t *testing.T) {
		s := &SiteConfig{CACert: "/abs/ca.pem"}
		p, err := s.ResolveCACertPath("/cfg")
		if err != nil {
			t.Fatal(err)
		}
		if p != "/abs/ca.pem" {
			t.Errorf("expected /abs/ca.pem, got %q", p)
		}
	})
}

func TestValidateCACert(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing file fails", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Sites = append(cfg.Sites, SiteConfig{
			Name:        "test",
			URL:         "https://example.com",
			Username:    "admin",
			AppPassword: "xxxx",
			CACert:      "nonexistent.pem",
		})
		cfg.path = filepath.Join(dir, "config.yaml")
		err := validate(&cfg)
		if err == nil {
			t.Fatal("expected error for missing ca_cert")
		}
		if !isErrInvalidCACert(err) {
			t.Errorf("expected ErrInvalidCACert, got %v", err)
		}
	})

	t.Run("garbage file fails", func(t *testing.T) {
		badPath := filepath.Join(dir, "bad.pem")
		if err := os.WriteFile(badPath, []byte("not a cert"), 0644); err != nil {
			t.Fatal(err)
		}
		cfg := DefaultConfig()
		cfg.Sites = append(cfg.Sites, SiteConfig{
			Name:        "test",
			URL:         "https://example.com",
			Username:    "admin",
			AppPassword: "xxxx",
			CACert:      badPath,
		})
		cfg.path = filepath.Join(dir, "config.yaml")
		err := validate(&cfg)
		if err == nil {
			t.Fatal("expected error for garbage ca_cert")
		}
		if !isErrInvalidCACert(err) {
			t.Errorf("expected ErrInvalidCACert, got %v", err)
		}
	})

	t.Run("valid PEM passes", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "test-ca"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
		if err != nil {
			t.Fatal(err)
		}
		block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		goodPath := filepath.Join(dir, "good.pem")
		if err := os.WriteFile(goodPath, block, 0644); err != nil {
			t.Fatal(err)
		}
		cfg := DefaultConfig()
		cfg.Sites = append(cfg.Sites, SiteConfig{
			Name:        "test",
			URL:         "https://example.com",
			Username:    "admin",
			AppPassword: "xxxx",
			CACert:      goodPath,
		})
		cfg.path = filepath.Join(dir, "config.yaml")
		err = validate(&cfg)
		if err != nil {
			t.Errorf("expected no error for valid PEM, got %v", err)
		}
	})
}

func isErrInvalidCACert(err error) bool {
	for err != nil {
		if err == ErrInvalidCACert {
			return true
		}
		if unwrapper, ok := err.(interface{ Unwrap() error }); ok {
			err = unwrapper.Unwrap()
		} else {
			break
		}
	}
	return false
}

func TestBaseURLPreservesPort(t *testing.T) {
	s := &SiteConfig{URL: "http://localhost:8888"}
	expected := "http://localhost:8888/wp-json/ultimate-security/v1"
	if got := s.BaseURL(); got != expected {
		t.Errorf("BaseURL() = %q, want %q", got, expected)
	}
}
