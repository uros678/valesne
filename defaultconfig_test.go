package main

import (
	"html"
	"regexp"
	"strings"
	"testing"
)

// TestDefaultConfigLoads: the config written on first start must load, with
// an example of every kind of check and Docker turned off.
func TestDefaultConfigLoads(t *testing.T) {
	cfg, err := loadTestConfig(t, defaultConfig)
	if err != nil {
		t.Fatalf("default config: %v", err)
	}
	if len(cfg.activeTargets()) != 2 || len(cfg.activeDNSServers()) != 2 || len(cfg.activeCerts()) != 1 {
		t.Errorf("hosts %d, DNS servers %d, certificates %d; want 2, 2, 1",
			len(cfg.activeTargets()), len(cfg.activeDNSServers()), len(cfg.activeCerts()))
	}
	if len(cfg.Docker) != 1 || len(cfg.activeDocker()) != 0 {
		t.Errorf("docker: %d blocks, %d active; want 1 block, turned off", len(cfg.Docker), len(cfg.activeDocker()))
	}
	if cfg.NtfyURL != "" || cfg.HeartbeatURL != "" {
		t.Errorf("the default config must not send anything")
	}
}

// TestHelpPageMatchesDefaultConfig: the HELP page explains the default
// config, so every example line on it (the <pre> blocks) is a line
// of defaultConfig, and every general setting in settingSections is in
// defaultConfig with the same value (or the value of its "e.g." comment).
func TestHelpPageMatchesDefaultConfig(t *testing.T) {
	lines := map[string]bool{}
	for _, l := range strings.Split(defaultConfig, "\n") {
		lines[strings.TrimSpace(l)] = true
	}

	page, err := webFS.ReadFile("web/help.html")
	if err != nil {
		t.Fatal(err)
	}
	pres := regexp.MustCompile(`(?s)<pre>(.*?)</pre>`).FindAllStringSubmatch(string(page), -1)
	if len(pres) < 4 {
		t.Fatalf("found %d example blocks on the HELP page, want 4", len(pres))
	}
	for _, pre := range pres {
		for _, l := range strings.Split(html.UnescapeString(pre[1]), "\n") {
			if l = strings.TrimSpace(l); l != "" && !lines[l] {
				t.Errorf("HELP example line not in defaultConfig: %s", l)
			}
		}
	}

	for _, sec := range settingSections {
		for _, s := range sec.Settings {
			re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(s.Key) + `\s*=\s*(.*)$`)
			m := re.FindStringSubmatch(defaultConfig)
			if m == nil {
				t.Errorf("%s: not in defaultConfig", s.Key)
				continue
			}
			value, comment, _ := strings.Cut(m[1], "#")
			if strings.TrimSpace(value) != s.Example && !strings.Contains(comment, s.Example) && !strings.Contains(defaultConfig, "("+s.Example+")") {
				t.Errorf("%s: HELP example %s is not the default %q or its example", s.Key, s.Example, strings.TrimSpace(m[1]))
			}
		}
	}
}
