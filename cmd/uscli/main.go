package main

import (
	"flag"
	"fmt"
	"os"

	tea "charm.land/bubbletea/v2"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/app"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/config"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/version"
)

func main() {
	showVersion := flag.Bool("version", false, "Print version and exit")
	debug := flag.Bool("debug", false, "Enable debug logging")
	configPath := flag.String("config", "", "Config file path")
	flag.Parse()

	if *showVersion {
		fmt.Printf("uscli %s (commit: %s, built: %s)\n", version.Version, version.GitCommit, version.BuildDate)
		os.Exit(0)
	}

	path := *configPath
	if path == "" {
		p, err := config.ConfigPath()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving config path: %v\n", err)
			os.Exit(1)
		}
		path = p
	}

	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	if *debug {
		cfg.Debug.Enabled = true
	}

	model := app.NewApp(cfg, path)
	p := tea.NewProgram(model)
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
