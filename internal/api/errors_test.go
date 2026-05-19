package api

import (
	"errors"
	"testing"
)

func TestErrorWithHint(t *testing.T) {
	t.Run("hint appended to Error()", func(t *testing.T) {
		e := NetworkError("request failed", errors.New("connection refused"))
		e.Hint = "set ca_cert or verify_ssl: false"
		msg := e.Error()
		if msg != "request failed: connection refused\nHint: set ca_cert or verify_ssl: false" {
			t.Errorf("unexpected Error(): %q", msg)
		}
	})
	t.Run("no hint when empty", func(t *testing.T) {
		e := AuthError(401, "authentication failed")
		msg := e.Error()
		if msg != "authentication failed" {
			t.Errorf("expected no hint, got %q", msg)
		}
	})
	t.Run("hint with no wrapped error", func(t *testing.T) {
		e := AuthError(401, "authentication failed")
		e.Hint = "WP_ENVIRONMENT_TYPE=local"
		msg := e.Error()
		if msg != "authentication failed\nHint: WP_ENVIRONMENT_TYPE=local" {
			t.Errorf("unexpected Error(): %q", msg)
		}
	})
}

func TestErrorUnwrap(t *testing.T) {
	orig := errors.New("underlying")
	e := NetworkError("request failed", orig)
	unwrapped := errors.Unwrap(e)
	if unwrapped != orig {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, orig)
	}
}

func TestErrorIsHelpers(t *testing.T) {
	netErr := NetworkError("fail", errors.New("x"))
	netErr.Hint = "some hint"
	if !IsNetwork(netErr) {
		t.Error("IsNetwork should return true")
	}

	authErr := AuthError(401, "fail")
	authErr.Hint = "some hint"
	if !IsAuth(authErr) {
		t.Error("IsAuth should return true")
	}
	if IsNetwork(authErr) {
		t.Error("IsNetwork should return false for auth error")
	}
}
