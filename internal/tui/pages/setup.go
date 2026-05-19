package pages

import (
	"context"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/api"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/config"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/messages"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/tui/theme"
)

type SetupPage struct {
	deps        messages.PageDeps
	form        *huh.Form
	siteName    string
	siteURL     string
	username    string
	appPassword string
	verifySSL   bool
	caCert      string
	result      string
	testing     bool
	complete    bool
	width       int
	height      int
}

func NewSetupPage() *SetupPage {
	return &SetupPage{verifySSL: true}
}

func (p *SetupPage) SetDeps(deps messages.PageDeps) {
	p.deps = deps
}

func (p *SetupPage) buildForm() {
	p.form = huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Key("site_name").
				Title("Site name").
				Description("A label for this site").
				Value(&p.siteName).
				Placeholder("production"),
			huh.NewInput().
				Key("site_url").
				Title("Site URL").
				Description("WordPress site root (not /wp-admin)").
				Value(&p.siteURL).
				Placeholder("https://example.com"),
			huh.NewInput().
				Key("username").
				Title("Username").
				Value(&p.username).
				Placeholder("admin"),
			huh.NewInput().
				Key("app_password").
				Title("Application Password").
				Description("WordPress Application Password").
				Value(&p.appPassword).
				Password(true),
			huh.NewInput().
				Key("ca_cert").
				Title("CA certificate path (optional)").
				Description("PEM CA bundle to trust (mkcert/Traefik/Local root). Blank for public certs.").
				Value(&p.caCert),
			huh.NewConfirm().
				Key("verify_ssl").
				Title("Verify SSL").
				Value(&p.verifySSL),
		),
	).WithWidth(60)
}

func (p *SetupPage) Init() tea.Cmd {
	p.buildForm()
	if p.form != nil {
		return p.form.Init()
	}
	return nil
}

func (p *SetupPage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if p.form == nil {
		p.buildForm()
		return p, p.form.Init()
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		p.width = msg.Width
		p.height = msg.Height
	case tea.KeyPressMsg:
		if msg.String() == "ctrl+t" && !p.testing {
			p.testing = true
			return p, p.testConnection()
		}
	case messages.ConnectionChangedMsg:
		p.testing = false
		if msg.Connected {
			p.result = theme.StatusOKStyle.Render("Connected! " + msg.Version)
			p.complete = true
		} else {
			p.result = theme.StatusErrStyle.Render(fmt.Sprintf("Failed: %v", msg.Err))
		}
		return p, nil
	}

	updated, cmd := p.form.Update(msg)
	if f, ok := updated.(*huh.Form); ok {
		p.form = f
	}

	return p, cmd
}

func (p SetupPage) View() tea.View {
	var b strings.Builder

	b.WriteString(theme.TitleStyle.Render("Connect to WordPress Site"))
	b.WriteString("\n\n")

	if p.form != nil {
		b.WriteString(p.form.View())
	}

	b.WriteString("\n\n")

	if httpWarning := p.httpWarning(); httpWarning != "" {
		b.WriteString(httpWarning)
		b.WriteString("\n\n")
	}

	b.WriteString(theme.LabelStyle.Render("<ctrl+t> test connection  <ctrl+c> cancel"))

	if p.result != "" {
		b.WriteString("\n\n")
		b.WriteString(p.result)
	}

	if p.testing {
		b.WriteString("\n\n")
		b.WriteString(theme.StatusMutedStyle.Render("Testing connection..."))
	}

	return tea.NewView(b.String())
}

func (p *SetupPage) httpWarning() string {
	url := strings.TrimSpace(p.siteURL)
	if !strings.HasPrefix(url, "http://") {
		return ""
	}
	if config.IsLoopbackOrDevHost(url) {
		return theme.StatusMutedStyle.Render("Local dev site detected — plaintext HTTP is allowed. WordPress needs WP_ENVIRONMENT_TYPE=local (or HTTPS) for Application Password auth over HTTP.")
	}
	return theme.StatusErrStyle.Render("Warning: http:// is insecure. Credentials are sent unencrypted. Use https:// for non-local sites.")
}

func (p *SetupPage) testConnection() tea.Cmd {
	return func() tea.Msg {
		url := strings.TrimSpace(p.siteURL)
		user := strings.TrimSpace(p.username)
		pass := strings.TrimSpace(p.appPassword)
		name := strings.TrimSpace(p.siteName)

		if url == "" || user == "" || pass == "" {
			return messages.ConnectionChangedMsg{
				Connected: false,
				Err:       fmt.Errorf("site URL, username, and application password are required"),
			}
		}

		if strings.HasSuffix(url, "/wp-admin") || strings.HasSuffix(url, "/wp-login.php") {
			return messages.ConnectionChangedMsg{
				Connected: false,
				Err:       fmt.Errorf("enter the site root URL, not /wp-admin or /wp-login.php"),
			}
		}

		v := p.verifySSL
		site := &config.SiteConfig{
			Name:        name,
			URL:         strings.TrimRight(url, "/"),
			Username:    user,
			AppPassword: pass,
			VerifySSL:   &v,
			CACert:      strings.TrimSpace(p.caCert),
		}
		if site.Name == "" {
			u := site.URL
			if strings.HasPrefix(u, "https://") {
				u = strings.TrimPrefix(u, "https://")
			} else if strings.HasPrefix(u, "http://") {
				u = strings.TrimPrefix(u, "http://")
			}
			site.Name = strings.Split(u, "/")[0]
		}

		apiCfg := config.DefaultConfig().API
		dir, _ := config.ConfigDir()
		client := api.NewClient(site, apiCfg, api.WithConfigDir(dir))

		info, err := api.NewConnectionService(client).TestConnection(context.Background())
		if err != nil {
			return messages.ConnectionChangedMsg{
				Site:      site,
				Connected: false,
				Err:       err,
			}
		}

		return messages.ConnectionChangedMsg{
			Site:      site,
			Connected: true,
			Version:   info.Version,
		}
	}
}
