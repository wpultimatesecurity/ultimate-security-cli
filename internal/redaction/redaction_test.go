package redaction

import (
	"strings"
	"testing"
)

func TestScrubLiterals(t *testing.T) {
	s := NewScrubber("S3cret!Password", "x1 real key value here")
	out := s.Scrub("config uses S3cret!Password and x1 real key value here")
	if strings.Contains(out, "S3cret") || strings.Contains(out, "real key") {
		t.Errorf("secrets leaked: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("expected placeholder: %q", out)
	}
	// Short literals are ignored to protect ordinary text.
	s2 := NewScrubber("ab")
	if got := s2.Scrub("ab"); got != "ab" {
		t.Errorf("short literal should not be scrubbed, got %q", got)
	}
}

func TestScrubKeyedAssignments(t *testing.T) {
	s := NewScrubber()
	cases := []string{
		`db_password=hunter2`,
		`DB_PASSWORD: hunter2`,
		`"api_key" = "sk-1234567890"`,
		`Authorization: Bearer abc.def.ghi`,
		`secret_token=abcdef123456`,
	}
	for _, in := range cases {
		out := s.Scrub(in)
		if strings.Contains(strings.ToLower(out), "hunter2") ||
			strings.Contains(out, "sk-1234567890") ||
			strings.Contains(out, "abc.def.ghi") ||
			strings.Contains(out, "abcdef123456") {
			t.Errorf("leak in %q -> %q", in, out)
		}
	}
}

func TestScrubPrivateKeyBlock(t *testing.T) {
	s := NewScrubber()
	in := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ\nabc\n-----END RSA PRIVATE KEY-----\ntrailing"
	out := s.Scrub(in)
	if strings.Contains(out, "MIIEow") {
		t.Errorf("private key leaked: %q", out)
	}
	if !strings.Contains(out, "trailing") {
		t.Errorf("trailing text must survive: %q", out)
	}
}

func TestScrubLongHex(t *testing.T) {
	s := NewScrubber()
	out := s.Scrub("token 0123456789abcdef0123456789abcdef0123456789 kept")
	if strings.Contains(out, "0123456789abcdef0123456789") {
		t.Errorf("long hex leaked: %q", out)
	}
	if !strings.Contains(out, "kept") {
		t.Errorf("neighbouring text must survive: %q", out)
	}
}

func TestScrubApplicationPassword(t *testing.T) {
	s := NewScrubber("abcd efgh ijkl mnop")
	out := s.Scrub("app password: abcd efgh ijkl mnop")
	if strings.Contains(out, "abcd") {
		t.Errorf("spaced app password leaked: %q", out)
	}
	// Ordinary prose with the same shape but no matching secret stays intact.
	if got := s.Scrub("New Site Login"); !strings.Contains(got, "New Site Login") {
		t.Errorf("ordinary text damaged: %q", got)
	}
}

func TestScrubMapAndSlice(t *testing.T) {
	s := NewScrubber("topsecret")
	m := s.Map(map[string]string{"path": "a/topsecret/b", "ok": "fine"})
	if strings.Contains(m["path"], "topsecret") {
		t.Errorf("map value leaked: %q", m["path"])
	}
	if m["ok"] != "fine" {
		t.Errorf("clean value damaged: %q", m["ok"])
	}
	sl := s.Slice([]string{"has topsecret inside", "clean"})
	if strings.Contains(sl[0], "topsecret") || sl[1] != "clean" {
		t.Errorf("slice scrub wrong: %v", sl)
	}
}
