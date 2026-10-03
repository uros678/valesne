package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// loadTestConfig writes body to a temporary config file and loads it.
func loadTestConfig(t *testing.T, body string) (config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return loadConfig(path)
}

const muteTestTargets = `targets = [ { name = "Server", host = "127.0.0.1" } ]` + "\n"

func TestMuteUntilNeedsATime(t *testing.T) {
	for _, bad := range []string{"2026-09-27", "18:00", "27.9.2026 18:00", "2026-09-27T18:00"} {
		_, err := loadTestConfig(t, `mute_until = "`+bad+`"`+"\n"+muteTestTargets)
		if err == nil || !strings.Contains(err.Error(), "mute_until") {
			t.Errorf("mute_until = %q: got %v, want an error", bad, err)
		}
	}
	cfg, err := loadTestConfig(t, `mute_until = "2026-09-27 18:00"`+"\n"+muteTestTargets)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 9, 27, 18, 0, 0, 0, time.Local)
	if !cfg.muteUntil.Equal(want) {
		t.Errorf("muteUntil = %v, want %v (local time)", cfg.muteUntil, want)
	}
}

func TestMuted(t *testing.T) {
	until := time.Date(2026, 9, 27, 18, 0, 0, 0, time.Local)
	before, after := until.Add(-time.Minute), until.Add(time.Minute)
	cases := []struct {
		name  string
		cfg   config
		at    time.Time
		check string
		want  bool
	}{
		{"nothing set", config{}, before, "Server", false},
		{"list only: listed", config{Mute: []string{"Server"}}, after, "Server", true},
		{"list only: other", config{Mute: []string{"Server"}}, before, "Router", false},
		{"time only: everything", config{muteUntil: until}, before, "Router", true},
		{"time only: passed", config{muteUntil: until}, after, "Router", false},
		{"both: listed, before", config{Mute: []string{"Server"}, muteUntil: until}, before, "Server", true},
		{"both: other, before", config{Mute: []string{"Server"}, muteUntil: until}, before, "Router", false},
		{"both: listed, passed", config{Mute: []string{"Server"}, muteUntil: until}, after, "Server", false},
	}
	for _, c := range cases {
		if got := c.cfg.muted(c.check, c.at); got != c.want {
			t.Errorf("%s: muted(%q) = %v, want %v", c.name, c.check, got, c.want)
		}
	}
}

// TestMuteKeepsState: a check that goes down while muted is reported after
// the mute ends when it is still down; one that came back sends nothing.
func TestMuteKeepsState(t *testing.T) {
	a, clock := testAlerter()
	muted := func(name string, lvl alertLevel, isMuted bool) []alertChange {
		clock.t = clock.t.Add(time.Minute)
		it := item(name, lvl)
		it.pending = isMuted
		return a.evaluate([]alertItem{it}, 2)
	}
	// Down during the mute, still down afterwards: DOWN after 2 rounds.
	for i := 0; i < 5; i++ {
		if got := muted("Server", levelFail, true); len(got) != 0 {
			t.Fatalf("alert while muted")
		}
	}
	if got := muted("Server", levelFail, false); len(got) != 0 {
		t.Fatalf("alert in the 1st round after the mute")
	}
	if got := muted("Server", levelFail, false); len(got) != 1 {
		t.Fatalf("no DOWN in the 2nd round after the mute")
	}
	// Down and back during the mute: nothing.
	for i := 0; i < 3; i++ {
		muted("Router", levelFail, true)
	}
	for i := 0; i < 3; i++ {
		if got := muted("Router", levelOK, false); len(got) != 0 {
			t.Fatalf("message for a check that came back during the mute")
		}
	}
}

// TestAfterRoundMute: afterRound leaves a muted check alone.
func TestAfterRoundMute(t *testing.T) {
	posts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { posts++ }))
	defer srv.Close()
	a, clock := testAlerter()
	down := snapshot{Results: []hostResult{{Name: "Server", Ping: probe{Error: "timeout"}, HTTP: probe{Skipped: true}}}}

	cfg := config{NtfyURL: srv.URL, AlertAfter: 1, Mute: []string{"Server"}}
	clock.t = clock.t.Add(time.Minute)
	a.afterRound(cfg, down)
	if posts != 0 {
		t.Fatalf("alert for a muted check")
	}
	cfg.Mute = nil
	clock.t = clock.t.Add(time.Minute)
	a.afterRound(cfg, down)
	if posts != 1 {
		t.Fatalf("no alert after the mute ended (%d posts)", posts)
	}
}

// TestMuteContainerByService: mute = ["web"] also mutes container
// "home-web-1" of compose service "web".
func TestMuteContainerByService(t *testing.T) {
	posts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { posts++ }))
	defer srv.Close()
	a, clock := testAlerter()
	snap := snapshot{Docker: []dockerResult{{Name: "Docker", Probe: probe{OK: true}, Containers: []containerResult{
		{Name: "home-web-1", Container: "home-web-1", Service: "web", Monitored: true, Probe: probe{Stopped: true, Error: "exited (exit code 0)"}},
	}}}}
	clock.t = clock.t.Add(time.Minute)
	a.afterRound(config{NtfyURL: srv.URL, AlertAfter: 1, Mute: []string{"web"}}, snap)
	if posts != 0 {
		t.Fatalf("alert for a container muted by its service name")
	}
}
