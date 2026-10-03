package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeClock is a clock that the test moves forward one round at a time.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func testAlerter() (*alerter, *fakeClock) {
	clock := &fakeClock{t: time.Date(2026, 9, 26, 17, 0, 0, 0, time.UTC)}
	a := newAlerter()
	a.now = clock.now
	return a, clock
}

func item(key string, lvl alertLevel) alertItem {
	return alertItem{key: key, kind: "host", name: key, level: lvl}
}

func TestEvaluateNeedsRoundsInARow(t *testing.T) {
	a, clock := testAlerter()
	steps := []struct {
		level alertLevel
		want  int // changes reported in this round
	}{
		{levelOK, 0},   // startup: nothing sent
		{levelFail, 0}, // 1st failed round
		{levelFail, 0}, // 2nd
		{levelOK, 0},   // blip over: streak reset
		{levelFail, 0},
		{levelFail, 0},
		{levelFail, 1}, // 3rd in a row: DOWN
		{levelFail, 0}, // still down: nothing new
		{levelOK, 0},
		{levelOK, 0},
		{levelOK, 1}, // recovered
	}
	for i, s := range steps {
		clock.t = clock.t.Add(time.Minute)
		got := a.evaluate([]alertItem{item("Server", s.level)}, 3)
		if len(got) != s.want {
			t.Fatalf("round %d: %d changes, want %d", i, len(got), s.want)
		}
		if i == 10 && got[0].for_ != 4*time.Minute {
			t.Errorf("recovered after %v, want 4m", got[0].for_)
		}
	}
}

func TestEvaluateDownAtStartupPendingAndRemoved(t *testing.T) {
	a, _ := testAlerter()
	pending := item("x", levelFail)
	pending.pending = true
	for i := 0; i < 5; i++ {
		if got := a.evaluate([]alertItem{pending}, 1); len(got) != 0 {
			t.Fatalf("pending item alerted")
		}
	}
	// A check that is already down when the app starts is reported.
	if got := a.evaluate([]alertItem{item("x", levelFail)}, 1); len(got) != 1 || got[0].from != levelOK {
		t.Fatalf("down at startup: %+v", got)
	}
	// Removed from the config: forgotten, no "recovered".
	if got := a.evaluate(nil, 1); len(got) != 0 || len(a.states) != 0 {
		t.Fatalf("removed check: %+v, states %d", got, len(a.states))
	}
}

func TestAlertItemsLevels(t *testing.T) {
	warn := probe{Warn: true, Error: "REFUSED"}
	snap := snapshot{
		DNSServers: []dnsServerResult{{Name: "dns", Probe: warn}},
		Certs: []certResult{
			{Name: "cert", certCheck: certCheck{Expires: "2026-10-16", Expiry: true, Probe: probe{Warn: true, Error: "20 days · renewal overdue"}}},
			{Name: "refused", certCheck: certCheck{Probe: probe{Warn: true, Error: "connection refused"}}},
		},
		Docker: []dockerResult{
			{Name: "all", Probe: probe{OK: true}, Containers: []containerResult{
				{Name: "stopped", Probe: probe{Stopped: true, Warn: true}},
			}},
			{Name: "down", Probe: probe{Error: "connection refused"}, Containers: []containerResult{
				{Name: "web", Probe: probe{Error: "connection refused"}},
			}},
		},
	}
	byName := func(items []alertItem) map[string]alertItem {
		m := map[string]alertItem{}
		for _, it := range items {
			m[it.name] = it
		}
		return m
	}

	got := byName(alertItems(snap, false))
	if got["dns"].level != levelOK {
		t.Errorf("DNS WARN alerts without alert_warn")
	}
	if got["cert"].level != levelWarn || got["cert"].pending {
		t.Errorf("certificate WARN does not alert")
	}
	if got["refused"].level != levelOK || !got["refused"].pending {
		t.Errorf("unreachable certificate address: level %v, pending %v", got["refused"].level, got["refused"].pending)
	}
	if got["stopped"].level != levelOK {
		t.Errorf("stopped container without a list alerts")
	}
	if got["down"].level != levelFail || !got["web"].pending {
		t.Errorf("daemon down: daemon %v, container pending %v", got["down"].level, got["web"].pending)
	}

	if got := byName(alertItems(snap, true)); got["dns"].level != levelWarn {
		t.Errorf("DNS WARN does not alert with alert_warn")
	}
}

func TestAlertItemsHostDetail(t *testing.T) {
	snap := snapshot{Results: []hostResult{{
		Name: "Internet",
		Ping: probe{Error: "timeout"},
		HTTP: probe{Error: "HTTP 503 (ok_status 200-399)"},
	}}}
	it := alertItems(snap, false)[0]
	if it.level != levelFail || it.detail != "ping: timeout, HTTP: HTTP 503 (ok_status 200-399)" {
		t.Errorf("got %v %q", it.level, it.detail)
	}
}

func TestAlertMessage(t *testing.T) {
	down := alertChange{item: alertItem{name: "Server", kind: "host", level: levelFail, detail: "ping: timeout"}}
	up := alertChange{item: alertItem{name: "Router", kind: "host", level: levelOK}, from: levelFail, for_: 12 * time.Minute}

	title, prio, _, lines, ok := alertMessage([]alertChange{down}, true)
	if !ok || title != "Server is DOWN" || prio != "high" || lines[0] != "DOWN  Server (host): ping: timeout" {
		t.Errorf("one down: %q %q %q", title, prio, lines)
	}
	title, prio, _, lines, _ = alertMessage([]alertChange{down, up}, true)
	if title != "1 down, 1 recovered" || prio != "high" || lines[1] != "OK    Router (host) recovered after 12m" {
		t.Errorf("down + up: %q %q %q", title, prio, lines)
	}
	if _, _, _, _, ok := alertMessage([]alertChange{up}, false); ok {
		t.Errorf("recovery sent with alert_recovered = false")
	}
}

// TestAfterRoundSendsAndRetries runs whole rounds against a fake ntfy server
// that is down for a while.
func TestAfterRoundSendsAndRetries(t *testing.T) {
	type msg struct{ title, prio, auth, body string }
	var got []msg
	failing := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		b, _ := io.ReadAll(r.Body)
		got = append(got, msg{r.Header.Get("Title"), r.Header.Get("Priority"), r.Header.Get("Authorization"), string(b)})
	}))
	defer srv.Close()

	a, clock := testAlerter()
	cfg := config{NtfyURL: srv.URL + "/topic", NtfyToken: "tk", AlertAfter: 1}
	round := func(ok bool) {
		clock.t = clock.t.Add(time.Minute)
		p := probe{OK: ok}
		if !ok {
			p.Error = "timeout"
		}
		a.afterRound(cfg, snapshot{Results: []hostResult{{Name: "Server", Ping: p, HTTP: probe{Skipped: true}}}})
	}

	round(true) // startup: nothing
	failing = true
	round(false) // DOWN, ntfy unreachable: kept
	if len(got) != 0 || len(a.unsent) != 1 {
		t.Fatalf("sent %d, unsent %d", len(got), len(a.unsent))
	}
	failing = false
	round(false) // nothing new, but the kept message goes out now
	if len(got) != 1 || got[0].title != "Earlier alerts" || !strings.Contains(got[0].body, "17:02 DOWN  Server (host): ping: timeout") {
		t.Fatalf("retry: %+v", got)
	}
	round(true) // recovered
	if len(got) != 2 || got[1].title != "Server recovered" || got[1].prio != "low" || got[1].auth != "Bearer tk" {
		t.Fatalf("recovered: %+v", got)
	}
	if len(a.unsent) != 0 {
		t.Errorf("unsent not cleared")
	}
}

// TestAlertStatus: the STATUS line of ntfy and the heartbeat follows the
// requests (failing since, unsent lines, back to ok), shows no URL, and
// starts over when a URL changes.
func TestAlertStatus(t *testing.T) {
	failing := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing {
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer srv.Close()

	a, clock := testAlerter()
	cfg := config{NtfyURL: srv.URL + "/topic", HeartbeatURL: srv.URL + "/beat", AlertAfter: 1}
	status := func() alertStatus { return a.state().status(cfg, clock.t) }
	round := func(ok bool) {
		clock.t = clock.t.Add(time.Minute)
		p := probe{OK: ok}
		if !ok {
			p.Error = "timeout"
		}
		a.afterRound(cfg, snapshot{Results: []hostResult{{Name: "Server", Ping: p, HTTP: probe{Skipped: true}}}})
	}

	if s := (alerterState{}).status(config{}, clock.t); s.Ntfy.On || s.Heartbeat.On {
		t.Errorf("nothing set: %+v", s)
	}
	if s := status(); !s.Ntfy.On || s.Ntfy.LastOK != "" || s.Heartbeat.LastOK != "" {
		t.Errorf("before the first round: %+v", s)
	}
	round(true) // 17:01, nothing to send
	if s := status(); s.Heartbeat.LastOK != "17:01" || s.Ntfy.LastOK != "" || s.Ntfy.Error != "" {
		t.Errorf("first round: %+v", s)
	}
	failing = true
	round(false) // 17:02, DOWN not sent
	round(false) // 17:03, retried
	s := status()
	if s.Ntfy.Error != "HTTP 502" || s.Ntfy.Since != "17:02" || s.Ntfy.Unsent != 1 ||
		s.Heartbeat.Error != "HTTP 502" || s.Heartbeat.Since != "17:02" || s.Heartbeat.LastOK != "17:01" {
		t.Errorf("failing: %+v", s)
	}
	failing = false
	round(false) // 17:04, the kept message goes out
	if s := status(); s.Ntfy.Error != "" || s.Ntfy.LastOK != "17:04" || s.Ntfy.Unsent != 0 || s.Heartbeat.LastOK != "17:04" {
		t.Errorf("back: %+v", s)
	}
	clock.t = clock.t.Add(24 * time.Hour)
	if s := status(); s.Ntfy.LastOK != "2026-09-26 17:04" {
		t.Errorf("next day: %+v", s)
	}
	cfg.NtfyURL = srv.URL + "/other" // changed: nothing sent yet
	if s := status(); !s.Ntfy.On || s.Ntfy.LastOK != "" {
		t.Errorf("changed URL: %+v", s)
	}
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close() // nothing listens there any more
	cfg.HeartbeatURL = gone.URL + "/secret-uuid"
	round(true)
	if s := status(); s.Heartbeat.Error == "" || strings.Contains(s.Heartbeat.Error, "secret") {
		t.Errorf("unreachable: %+v", s.Heartbeat)
	}
}
