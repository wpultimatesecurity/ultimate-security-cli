package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func init() {
	Register(Simple{
		Meta: Meta{
			ID:          "WP_CONFIG_PERMISSIONS",
			Title:       "wp-config.php permissions are too open",
			Category:    CatFS,
			Description: "wp-config.php holds database credentials and salts. It should not be writable by other users and ideally not readable by them either (recommended: 600, 640 or 660).",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/security/security/",
			},
		},
		Run: runWpConfigPerms,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "WEAK_FILE_PERMISSIONS",
			Title:       "World-writable files inside the web root",
			Category:    CatFS,
			Description: "Files writable by every user on the host can be modified by any compromised local account. Counts are bounded; on very large sites the walk may stop early (noted in evidence).",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/security/security/",
			},
		},
		Run: runWeakPerms,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "EXPOSED_ENV_FILE",
			Title:       "Environment file inside the web root",
			Category:    CatExposure,
			Description: "A .env file sits in the web root. Depending on server configuration it may be directly downloadable; .env files conventionally hold secrets.",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/security/security/",
			},
		},
		Run: runExposedEnv,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "EXPOSED_GIT_DIRECTORY",
			Title:       ".git directory inside the web root",
			Category:    CatExposure,
			Description: "A .git directory in the web root can expose the full source history, including committed secrets, if the web server serves its contents.",
			References: []string{
				"https://owasp.org/www-project-web-security-testing-guide/",
			},
		},
		Run: runExposedGit,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "EXPOSED_DEBUG_LOG",
			Title:       "WordPress debug log is present in the web root",
			Category:    CatExposure,
			Description: "wp-content/debug.log exists and is non-empty. If the web server serves it, the log can disclose paths, queries, and stack traces.",
			References: []string{
				"https://developer.wordpress.org/debugging-in-wordpress/",
			},
		},
		Run: runExposedDebugLog,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "EXPOSED_BACKUP_FILE",
			Title:       "Database dumps or backup archives inside the web root",
			Category:    CatExposure,
			Description: "SQL dumps or backup archives in the web root often contain the full database — users, password hashes, configuration. If served, they are a direct compromise path.",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/security/security/",
			},
		},
		Run: runExposedBackups,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "EXPOSED_EDITOR_BACKUP",
			Title:       "Editor backup or temporary files in the web root",
			Category:    CatExposure,
			Description: "Files like wp-config.php~, *.bak, *.orig, or vim swap files next to live code can expose source (and for wp-config, secrets) when requested directly.",
			References: []string{
				"https://owasp.org/www-project-web-security-testing-guide/",
			},
		},
		Run: runEditorBackups,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "PHP_EXECUTION_IN_UPLOADS",
			Title:       "PHP files inside wp-content/uploads",
			Category:    CatHardning,
			Description: "PHP files in the uploads directory are executable web paths where nothing should execute. Their presence usually means malicious upload or a broken deployment; WordPress never ships PHP there.",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/security/security/",
			},
		},
		Run: runPHPInUploads,
	})
}

// permFinding builds the WP_CONFIG_PERMISSIONS finding for a given mode.
func configPermFinding(mode os.FileMode) Finding {
	m := Meta{ID: "WP_CONFIG_PERMISSIONS", Title: "wp-config.php permissions are too open", Category: CatFS,
		References: []string{"https://developer.wordpress.org/advanced-administration/security/security/"}}
	perm := mode.Perm()
	ev := map[string]string{"file": "wp-config.php", "mode": fmt.Sprintf("%04o", uint32(perm))}
	if perm&0o002 != 0 {
		return Finding{ID: m.ID, Title: m.Title, Category: m.Category,
			Severity: SevHigh, Status: StatusFailed, Confidence: ConfHigh,
			Description:    "wp-config.php is writable by every user on the host; any compromised local account can alter database credentials and site code paths.",
			Evidence:       ev,
			Recommendation: "chmod 600 wp-config.php (or 660 when group write is required by the host).",
			References:     m.References,
		}
	}
	if perm&0o020 != 0 {
		return Finding{ID: m.ID, Title: m.Title, Category: m.Category,
			Severity: SevMedium, Status: StatusFailed, Confidence: ConfHigh,
			Description:    "wp-config.php is group-writable. Acceptable only when the group is strictly the web server's own group.",
			Evidence:       ev,
			Recommendation: "Prefer chmod 600 or 640 for wp-config.php.",
			References:     m.References,
		}
	}
	if perm&0o004 != 0 {
		return Finding{ID: m.ID, Title: "wp-config.php is world-readable", Category: m.Category,
			Severity: SevLow, Status: StatusFailed, Confidence: ConfHigh,
			Description:    "wp-config.php can be read by every local user; on shared hosts that includes other tenants' processes.",
			Evidence:       ev,
			Recommendation: "chmod 600 wp-config.php to limit reads to the owner (and web server group when needed: 640).",
			References:     m.References,
		}
	}
	return Finding{ID: m.ID, Title: "wp-config.php permissions are restricted", Category: m.Category,
		Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
		Description: "wp-config.php is not writable by others and not world-readable.",
		Evidence:    ev,
	}
}

func runWpConfigPerms(ctx *Context) []Finding {
	cfg := ctx.Site.Config
	if cfg == nil || !cfg.Exists {
		f := Meta{ID: "WP_CONFIG_PERMISSIONS", Title: "wp-config.php permissions", Category: CatFS,
			References: []string{"https://developer.wordpress.org/advanced-administration/security/security/"}}
		return []Finding{f.skipf("wp-config.php not found or unreadable")}
	}
	return []Finding{configPermFinding(os.FileMode(cfg.Mode))}
}

func runWeakPerms(ctx *Context) []Finding {
	m := Meta{ID: "WEAK_FILE_PERMISSIONS", Title: "World-writable files inside the web root", Category: CatFS,
		References: []string{"https://developer.wordpress.org/advanced-administration/security/security/"}}
	res := walk(ctx.Site.Path, defaultCaps(ctx.Deep), func(rel string) bool { return false })
	weak := res.WorldWritableFiles + res.WorldWritableDirs
	ev := map[string]string{
		"world_writable_files":       fmt.Sprint(res.WorldWritableFiles),
		"world_writable_directories": fmt.Sprint(res.WorldWritableDirs),
		"files_examined":             fmt.Sprint(res.Files),
	}
	if res.Truncated {
		ev["note"] = "walk stopped early (time/file budget); results are partial — rerun with --deep for full coverage"
	}
	if weak == 0 {
		return []Finding{Finding{ID: m.ID, Title: "No world-writable files", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "No world-writable files or directories were found in the web root.",
			Evidence:    ev}}
	}
	sev := SevMedium
	if res.WorldWritableFiles > 0 {
		sev = SevMedium
	}
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: sev, Status: StatusFailed, Confidence: ConfHigh,
		Description:    fmt.Sprintf("%d world-writable files/directories were found under the web root. Any local user (or compromised service account) can modify them.", weak),
		Evidence:       ev,
		Recommendation: "Remove world-writable bits (chmod o-w). Directories almost never need them; use the web server's own group instead.",
		References:     m.References,
	}}
}

func runExposedEnv(ctx *Context) []Finding {
	m := Meta{ID: "EXPOSED_ENV_FILE", Title: "Environment file inside the web root", Category: CatExposure,
		References: []string{"https://developer.wordpress.org/advanced-administration/security/security/"}}
	var found []string
	entries, err := os.ReadDir(ctx.Site.Path)
	if err != nil {
		return []Finding{m.skipf("web root not readable")}
	}
	for _, e := range entries {
		n := e.Name()
		if n == ".env" || (strings.HasPrefix(n, ".env.") && !e.IsDir()) {
			found = append(found, n)
		}
	}
	if len(found) == 0 {
		return []Finding{Finding{ID: m.ID, Title: "No .env file in web root", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "No environment files were found in the web root."}}
	}
	sort.Strings(found)
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevHigh, Status: StatusFailed, Confidence: ConfMedium,
		Description:    ".env files conventionally contain secrets (database passwords, API keys). Depending on server configuration the file may be directly downloadable. wpus did not read its contents.",
		Evidence:       map[string]string{"files": strings.Join(found, ", ")},
		Recommendation: "Move the file out of the web root, or block access to dotfiles in the web server configuration; rotate any secrets that were exposed.",
		References:     m.References,
	}}
}

func runExposedGit(ctx *Context) []Finding {
	m := Meta{ID: "EXPOSED_GIT_DIRECTORY", Title: ".git directory inside the web root", Category: CatExposure,
		References: []string{"https://owasp.org/www-project-web-security-testing-guide/"}}
	gitPath := filepath.Join(ctx.Site.Path, ".git")
	st, err := os.Stat(gitPath)
	switch {
	case err != nil:
		return []Finding{Finding{ID: m.ID, Title: "No .git directory", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "No .git directory was found in the web root."}}
	case st.IsDir():
		return []Finding{Finding{
			ID: m.ID, Title: m.Title, Category: m.Category,
			Severity: SevMedium, Status: StatusFailed, Confidence: ConfMedium,
			Description:    "A .git directory exists in the web root. If the web server serves dotfiles or PHP-generated directory listings, the repository history (including committed secrets) is retrievable.",
			Evidence:       map[string]string{"path": ".git"},
			Recommendation: "Deploy sites without the VCS metadata, or deny access to .git in the web server configuration.",
			References:     m.References,
		}}
	default:
		return []Finding{Finding{ID: m.ID, Title: ".git present (not a directory)", Category: m.Category,
			Severity: SevInfo, Status: StatusUnknown, Confidence: ConfLow,
			Description: "A .git entry exists but is not a directory; skipping."}}
	}
}

func runExposedDebugLog(ctx *Context) []Finding {
	m := Meta{ID: "EXPOSED_DEBUG_LOG", Title: "WordPress debug log is present in the web root", Category: CatExposure,
		References: []string{"https://developer.wordpress.org/debugging-in-wordpress/"}}
	candidates := []string{
		filepath.Join(ctx.Site.ContentPath, "debug.log"),
		filepath.Join(ctx.Site.Path, "debug.log"),
	}
	var hit string
	for _, c := range candidates {
		if fileSize(c) > 0 {
			hit = c
			break
		}
	}
	if hit == "" {
		return []Finding{Finding{ID: m.ID, Title: "No debug.log exposure", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "No non-empty debug.log was found in the web root."}}
	}
	rel, err := filepath.Rel(ctx.Site.Path, hit)
	if err != nil {
		rel = hit
	}
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevLow, Status: StatusFailed, Confidence: ConfMedium,
		Description:    "A non-empty debug.log file exists inside the web root. If the web server serves it, it can disclose paths, queries, and error details.",
		Evidence:       map[string]string{"path": filepath.ToSlash(rel)},
		Recommendation: "Disable WP_DEBUG_LOG on production or store the log outside the web root; block direct access to it.",
		References:     m.References,
	}}
}

func runExposedBackups(ctx *Context) []Finding {
	m := Meta{ID: "EXPOSED_BACKUP_FILE", Title: "Database dumps or backup archives inside the web root", Category: CatExposure,
		References: []string{"https://developer.wordpress.org/advanced-administration/security/security/"}}
	dumpExt := []string{".sql", ".sql.gz", ".dump", ".mysql"}
	archiveExt := []string{".zip", ".tar", ".tar.gz", ".tgz", ".7z", ".rar"}
	backupHint := []string{"backup", "bak", "dump", "db-", "-db", "snapshot"}

	res := walk(ctx.Site.Path, defaultCaps(ctx.Deep), func(rel string) bool {
		base := strings.ToLower(filepath.Base(rel))
		if hasExtension(base, dumpExt...) {
			return true
		}
		if hasExtension(base, archiveExt...) {
			for _, hint := range backupHint {
				if strings.Contains(base, hint) {
					return true
				}
			}
		}
		return false
	})
	ev := map[string]string{"files_examined": fmt.Sprint(res.Files)}
	if res.Truncated {
		ev["note"] = "walk stopped early (budget); results partial — rerun with --deep"
	}
	if len(res.Matches) == 0 {
		return []Finding{Finding{ID: m.ID, Title: "No backup files in web root", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfMedium,
			Description: "No database dumps or obvious backup archives were found in the web root.",
			Evidence:    ev}}
	}
	ev["matches"] = strings.Join(res.Matches, ", ")
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevHigh, Status: StatusFailed, Confidence: ConfMedium,
		Description:    "Potential database dumps or backup archives exist inside the web root. If the web server serves them, the full database (users, password hashes, secrets) is downloadable.",
		Evidence:       ev,
		Recommendation: "Move backups outside the web root (or to off-site storage) and block archive/dump extensions in the server configuration.",
		References:     m.References,
	}}
}

func runEditorBackups(ctx *Context) []Finding {
	m := Meta{ID: "EXPOSED_EDITOR_BACKUP", Title: "Editor backup or temporary files in the web root", Category: CatExposure,
		References: []string{"https://owasp.org/www-project-web-security-testing-guide/"}}
	var found []string
	entries, err := os.ReadDir(ctx.Site.Path)
	if err != nil {
		return []Finding{m.skipf("web root not readable")}
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, "~") || strings.HasSuffix(n, ".bak") ||
			strings.HasSuffix(n, ".orig") || strings.HasSuffix(n, ".swp") ||
			strings.HasSuffix(n, ".swo") || strings.HasSuffix(n, ".save") {
			found = append(found, n)
		}
	}
	if len(found) == 0 {
		return []Finding{Finding{ID: m.ID, Title: "No editor backup files", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "No editor backup or swap files were found in the web root."}}
	}
	sort.Strings(found)
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevLow, Status: StatusFailed, Confidence: ConfHigh,
		Description:    "Editor backup/temporary files exist in the web root; when requested directly they can expose source code (wp-config.php~ would expose credentials).",
		Evidence:       map[string]string{"files": strings.Join(found, ", ")},
		Recommendation: "Delete backup/temporary files from the web root.",
		References:     m.References,
	}}
}

func runPHPInUploads(ctx *Context) []Finding {
	m := Meta{ID: "PHP_EXECUTION_IN_UPLOADS", Title: "PHP files inside wp-content/uploads", Category: CatHardning,
		References: []string{"https://developer.wordpress.org/advanced-administration/security/security/"}}
	if !fileExists(ctx.Site.UploadsPath) {
		return []Finding{m.skipf("uploads directory does not exist")}
	}
	res := walk(ctx.Site.UploadsPath, defaultCaps(ctx.Deep), func(rel string) bool {
		return hasExtension(rel, ".php", ".php3", ".php5", ".php7", ".phtml", ".phar")
	})
	ev := map[string]string{"files_examined": fmt.Sprint(res.Files)}
	if res.Truncated {
		ev["note"] = "walk stopped early (budget); results partial — rerun with --deep"
	}
	if len(res.Matches) == 0 {
		return []Finding{Finding{ID: m.ID, Title: "No PHP in uploads", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "No PHP files were found in the uploads directory.",
			Evidence:    ev}}
	}
	ev["matches"] = strings.Join(res.Matches, ", ")
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevMedium, Status: StatusFailed, Confidence: ConfHigh,
		Description:    fmt.Sprintf("%d PHP file(s) were found inside wp-content/uploads. WordPress never ships PHP there; these are usually leftovers from a compromise or a broken deployment and are web-executable paths.", len(res.Matches)),
		Evidence:       ev,
		Recommendation: "Review the listed files, remove them if unwanted, and disable PHP execution in uploads at the web server level.",
		References:     m.References,
	}}
}
