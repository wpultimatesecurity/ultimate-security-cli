package wordpress

import (
	"strings"
	"testing"
)

// FuzzVersionCompare pins the invariants every consumer of the comparator
// depends on. Affected-version range matching is security-critical: an
// inconsistent ordering silently turns a vulnerable install into a "safe"
// result. A crash, a non-normalized result, or a broken antisymmetry/
// transitivity property is a bug regardless of input.
func FuzzVersionCompare(f *testing.F) {
	seeds := []string{
		"1.0", "1.0.0", "1.0-beta", "1.0beta1", "1.0-RC1", "1.0rc2", "1.0-dev",
		"1.0-alpha1", "1.0-p1", "2.0.2a", "20260911", "4.0000002", "6.8.2",
		"8.2", "v1.2", "1.0+meta", "1.0_1", "", "#1.0", "0", "9.9.9",
		// Inputs that canonicalize to the empty string: PHP's own ordering is
		// inconsistent for them (see the antisymmetry note below).
		". ", ".", " ",
		// Case-sensitive name comparison and unknown name classes.
		"A   ", "a", "zz", "beta", "RC",
	}
	for _, a := range seeds {
		for _, b := range seeds {
			f.Add(a, b)
		}
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		ab := VersionCompare(a, b)
		if ab < -1 || ab > 1 {
			t.Fatalf("VersionCompare(%q, %q) = %d, want -1..1", a, b, ab)
		}
		ba := VersionCompare(b, a)
		if versionOrderable(a) && versionOrderable(b) && ab != -ba {
			t.Fatalf("antisymmetry violated: compare(%q,%q)=%d but compare(%q,%q)=%d", a, b, ab, b, a, ba)
		}
		if versionOrderable(a) && VersionCompare(a, a) != 0 {
			t.Fatalf("reflexivity violated for %q", a)
		}
		if !versionOrderable(a) || !versionOrderable(b) {
			return
		}
		for _, c := range []string{"1.0", "1.0-rc1", "20260911"} {
			ac, cb := VersionCompare(a, c), VersionCompare(c, b)
			if ac <= 0 && cb <= 0 && ab > 0 {
				t.Fatalf("transitivity violated: %q <= %q <= %q but %q > %q", a, c, b, a, b)
			}
			if ac >= 0 && cb >= 0 && ab < 0 {
				t.Fatalf("transitivity violated: %q >= %q >= %q but %q < %q", a, c, b, a, b)
			}
		}
	})
}

// versionOrderable reports whether PHP's ordering is well-behaved for s.
//
// Two documented PHP quirks break the ordering invariants, and the port
// reproduces both because matching the platform is the entire point of the
// comparator (WordPress orders versions the same way):
//
//   - a "#" anywhere in the string is ordered through the special-forms table
//     (where "#" sorts between "rc" and "pl") instead of being compared as
//     text, so the relation stops being a total preorder:
//     version_compare("1+1A","1.0")=1 and ("1.0","1#")=0 but
//     ("1+1A","1#")=-1 on PHP 8.5, and the leading-hatch form
//     "#1.0"/"20260911"/"9.9.9" shows the same break;
//   - a value that canonicalizes to the empty string compares "less than"
//     everything in both directions, and even against itself
//     (version_compare(".", ".") = -1).
//
// Vulnerability ranges never contain "#" and are never empty, so far this does
// not affect affected-version matching. These invariants exist to catch a
// regression that would make the port diverge from PHP.
func versionOrderable(s string) bool {
	return !strings.ContainsRune(s, '#') && canonicalizeVersion(s) != ""
}

// FuzzVersionBetween checks that range matching never panics and stays
// consistent with the comparator.
func FuzzVersionBetween(f *testing.F) {
	f.Add("1.2.3", "1.0", true, "1.3", false)
	f.Add("", "", false, "", false)
	f.Add("6.8.2", "6.8", true, "6.8.2", true)
	f.Fuzz(func(t *testing.T, v, from string, fromInc bool, to string, toInc bool) {
		got := VersionBetween(v, from, fromInc, to, toInc)
		// VersionBetween must agree with the comparator it is built on: a
		// version inside both bounds is in range, by definition.
		lowerOK := from == "" || from == "*" || VersionCompare(v, from) > 0 ||
			(VersionCompare(v, from) == 0 && fromInc)
		upperOK := to == "" || to == "*" || VersionCompare(v, to) < 0 ||
			(VersionCompare(v, to) == 0 && toInc)
		if lowerOK && upperOK && !got {
			t.Fatalf("VersionBetween(%q, [%q,%v], %q,%v) = false but both bounds accept it", v, from, fromInc, to, toInc)
		}
	})
}

// FuzzParseWpConfig pins the parser's safety property: wp-config.php is
// attacker-controlled input parsed statically, so it must never panic, never
// read unbounded input, and never surface a secret it did not find.
func FuzzParseWpConfig(f *testing.F) {
	f.Add("<?php define( 'WP_DEBUG', true ); $table_prefix = 'wp_';")
	f.Add("<?php define('DB_PASSWORD', 'hunter2hunter2'); // comment")
	f.Add("<?php /* unterminated")
	f.Add("<?php define( 'AUTH_KEY', \"quoted\\\"key\" );")
	f.Add(strings.Repeat("<?php define('X','Y');", 500))
	f.Fuzz(func(t *testing.T, src string) {
		cfg := (&WpConfig{Defines: map[string]string{}}).parse(src)
		for _, secret := range cfg.SecretLiterals {
			if len(secret) == 0 {
				t.Fatal("empty secret literal collected")
			}
		}
		if len(cfg.Defines) > 4096 {
			t.Fatalf("define map grew unbounded: %d entries", len(cfg.Defines))
		}
		// Values stay raw PHP text: parsing must not evaluate anything.
		for _, raw := range cfg.Defines {
			if strings.Contains(raw, "<?php") {
				t.Fatal("parser produced PHP source instead of a literal value")
			}
		}
	})
}
