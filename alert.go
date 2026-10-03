package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Alerting: after every complete round the results are compared with what
// was last reported, and state changes are sent as one ntfy notification.
//
//   - A change is reported only after it has been seen alert_after rounds in
//     a row, so one lost ping does not wake anybody up (also for recoveries,
//     so a flapping host does not send a pair of messages every round).
//   - Everything starts as "OK, nothing reported": nothing is sent on startup
//     or a config reload for checks that are fine; one that is already down
//     is reported after alert_after rounds.
//   - FAIL always alerts; WARN only for certificates (the renewal is overdue),
//     or for everything with alert_warn = true. A stopped container that is
//     not monitored is only shown, never alerted, and so is a certificate
//     that cannot be reached or is not valid (only its expiry alerts).
//   - A message that cannot be sent (e.g. the internet is down) is kept and
//     sent with the next one.
//   - mute / mute_until silence checks (or everything) e.g. for maintenance;
//     a muted check keeps its state (see afterRound).

type alertLevel int

const (
	levelOK alertLevel = iota
	levelWarn
	levelFail
)

// alertItem is the state of one check (host, DNS server, certificate,
// daemon, container) after a round, reduced to what alerting needs.
type alertItem struct {
	key     string
	kind    string // "host", "DNS server", ...
	name    string
	aliases []string // other names mute matches (a container's name and compose service)
	level   alertLevel
	detail  string // error text, e.g. "ping: timeout"
	pending bool   // no result yet: leave its state alone
}

// alertItems turns a snapshot into alert items.
func alertItems(snap snapshot, warnAll bool) []alertItem {
	var items []alertItem
	fromProbe := func(p probe, warnAlerts bool) (alertLevel, string) {
		switch {
		case p.OK:
			return levelOK, ""
		case p.Warn && !warnAlerts:
			return levelOK, ""
		case p.Warn:
			return levelWarn, p.Error
		}
		return levelFail, p.Error
	}

	for _, r := range snap.Results {
		it := alertItem{key: "host|" + r.key(), kind: "host", name: r.Name, pending: r.Pending}
		var details []string
		for _, pp := range []struct {
			label string
			p     probe
		}{{"ping", r.Ping}, {"HTTP", r.HTTP}} {
			if pp.p.Skipped || pp.p.Pending {
				continue
			}
			lvl, d := fromProbe(pp.p, warnAll)
			if lvl > it.level {
				it.level = lvl
			}
			if lvl > levelOK {
				details = append(details, pp.label+": "+d)
			}
		}
		it.detail = strings.Join(details, ", ")
		items = append(items, it)
	}
	for _, d := range snap.DNSServers {
		lvl, detail := fromProbe(d.Probe, warnAll)
		items = append(items, alertItem{key: "dns|" + d.key(), kind: "DNS server", name: d.Name,
			level: lvl, detail: detail, pending: d.Probe.Pending})
	}
	for _, c := range snap.Certs {
		// Only the expiry alerts (WARN = renewal overdue, even without
		// alert_warn); an invalid certificate is only shown. When no
		// certificate could be read (server unreachable), nothing is known
		// about the expiry: the state is left alone, so an earlier "renewal
		// overdue" is not followed by a false "recovered".
		lvl, detail := fromProbe(c.Probe, true)
		if !c.Expiry {
			lvl, detail = levelOK, ""
		}
		unknown := c.Expires == "" && !c.Probe.OK
		items = append(items, alertItem{key: "cert|" + c.key(), kind: "certificate", name: c.Name,
			level: lvl, detail: detail, pending: c.Probe.Pending || unknown})
	}
	for _, d := range snap.Docker {
		lvl, detail := fromProbe(d.Probe, warnAll)
		items = append(items, alertItem{key: "docker|" + d.key(), kind: "Docker daemon", name: d.Name,
			level: lvl, detail: detail, pending: d.Probe.Pending})
		// With the daemon down nothing is known about its containers: the
		// daemon alert covers them, and their state is left alone.
		daemonDown := !d.Probe.OK
		for _, c := range d.Containers {
			// A monitored container is known by its configured name, so
			// "not found" after compose down and the new container after
			// compose up are the same check (DOWN, then recovered).
			name := c.Name
			if c.MonitorName != "" {
				name = c.MonitorName
			}
			it := alertItem{key: "container|" + d.key() + "|" + name, kind: "container", name: name,
				aliases: []string{c.Name, c.Container, c.Service}, pending: c.Probe.Pending || daemonDown}
			if c.idle() {
				it.level = levelOK // only shown on the page
			} else {
				it.level, it.detail = fromProbe(c.Probe, warnAll)
			}
			items = append(items, it)
		}
	}
	return items
}

// alertState is what alerting remembers about one check.
type alertState struct {
	reported  alertLevel // the last level that was reported (or assumed: OK)
	since     time.Time  // when reported was set, for "recovered after 12m"
	candidate alertLevel // a level different from reported ...
	streak    int        // ... seen this many rounds in a row
}

// alertChange is one state change to report.
type alertChange struct {
	item alertItem
	from alertLevel
	for_ time.Duration // how long the previous level lasted
}

type alerter struct {
	states map[string]*alertState
	unsent []string // lines of messages that could not be sent
	client *http.Client
	now    func() time.Time
	ntfy   channelState // last sends to ntfy
	beat   channelState // last heartbeat requests
}

// channelState is how the last requests to ntfy or the heartbeat URL went,
// for the line on the STATUS page. key is the URL (+ token) the results
// belong to: a changed setting starts over.
type channelState struct {
	key       string
	lastOK    time.Time
	err       string    // error of the last request, empty when it worked
	failSince time.Time // first failed request in a row
}

// result records one request.
func (c *channelState) result(now time.Time, err error) {
	if err == nil {
		c.lastOK, c.err, c.failSince = now, "", time.Time{}
		return
	}
	if c.err == "" {
		c.failSince = now
	}
	c.err = shortNetError(err)
}

// alertStatus is the state of ntfy and the heartbeat as the STATUS page shows
// it (never the URLs, they are secret).
type alertStatus struct {
	Ntfy      channelStatus `json:"ntfy"`
	Heartbeat channelStatus `json:"heartbeat"`
}

type channelStatus struct {
	On     bool   `json:"on"`               // the URL is set
	LastOK string `json:"lastOk,omitempty"` // last request that worked
	Error  string `json:"error,omitempty"`  // the last request failed
	Since  string `json:"since,omitempty"`  // failing since
	Unsent int    `json:"unsent,omitempty"` // ntfy: lines kept for the next message
}

// alerterState is what the store keeps of the alerter after every round.
type alerterState struct {
	ntfy, beat channelState
	unsent     int
}

func (a *alerter) state() alerterState {
	return alerterState{ntfy: a.ntfy, beat: a.beat, unsent: len(a.unsent)}
}

// status turns the alerter state into what the page shows for cfg. A setting
// changed since the last round shows as on, nothing sent yet.
func (st alerterState) status(cfg config, now time.Time) alertStatus {
	view := func(c channelState, key string) channelStatus {
		if key == "" {
			return channelStatus{}
		}
		out := channelStatus{On: true}
		if c.key != key {
			return out
		}
		if !c.lastOK.IsZero() {
			out.LastOK = shortStamp(c.lastOK, now)
		}
		if c.err != "" {
			out.Error, out.Since = c.err, shortStamp(c.failSince, now)
		}
		return out
	}
	out := alertStatus{Ntfy: view(st.ntfy, ntfyKey(cfg)), Heartbeat: view(st.beat, cfg.HeartbeatURL)}
	if out.Ntfy.On && st.ntfy.key == ntfyKey(cfg) {
		out.Ntfy.Unsent = st.unsent
	}
	return out
}

func ntfyKey(cfg config) string {
	if cfg.NtfyURL == "" {
		return ""
	}
	return cfg.NtfyURL + "\x00" + cfg.NtfyToken
}

// shortStamp is "15:04" today, otherwise with the date.
func shortStamp(t, now time.Time) string {
	if t.Format("2006-01-02") == now.Format("2006-01-02") {
		return t.Format("15:04")
	}
	return t.Format("2006-01-02 15:04")
}

func newAlerter() *alerter {
	return &alerter{
		states: map[string]*alertState{},
		client: &http.Client{Timeout: 10 * time.Second},
		now:    time.Now,
	}
}

const maxUnsent = 50

// evaluate updates the states with one round and returns the changes to
// report. Checks no longer in the config are forgotten.
func (a *alerter) evaluate(items []alertItem, after int) []alertChange {
	now := a.now()
	seen := map[string]bool{}
	var changes []alertChange
	for _, it := range items {
		seen[it.key] = true
		st := a.states[it.key]
		if st == nil {
			st = &alertState{reported: levelOK, since: now}
			a.states[it.key] = st
		}
		if it.pending {
			continue
		}
		if it.level == st.reported {
			st.streak = 0
			continue
		}
		if it.level == st.candidate && st.streak > 0 {
			st.streak++
		} else {
			st.candidate, st.streak = it.level, 1
		}
		if st.streak < after {
			continue
		}
		changes = append(changes, alertChange{item: it, from: st.reported, for_: now.Sub(st.since)})
		st.reported, st.since, st.streak = it.level, now, 0
	}
	for k := range a.states {
		if !seen[k] {
			delete(a.states, k)
		}
	}
	return changes
}

// message builds the ntfy title, priority, tags and body for the changes.
// With recovered = false recoveries are left out; ok is false when nothing
// is left to send.
func alertMessage(changes []alertChange, recovered bool) (title, priority, tags string, lines []string, ok bool) {
	var down, warn, up int
	var last alertChange
	for _, c := range changes {
		var line string
		switch c.item.level {
		case levelFail:
			down++
			line = "DOWN  " + c.item.name + " (" + c.item.kind + ")"
		case levelWarn:
			warn++
			line = "WARN  " + c.item.name + " (" + c.item.kind + ")"
		default:
			if !recovered {
				continue
			}
			up++
			line = "OK    " + c.item.name + " (" + c.item.kind + ") recovered after " + shortDuration(c.for_)
		}
		if c.item.level != levelOK && c.item.detail != "" {
			line += ": " + c.item.detail
		}
		lines = append(lines, line)
		last = c
	}
	if len(lines) == 0 {
		return "", "", "", nil, false
	}
	switch {
	case down > 0:
		priority, tags = "high", "rotating_light"
	case warn > 0:
		priority, tags = "default", "warning"
	default:
		priority, tags = "low", "white_check_mark"
	}
	if len(lines) == 1 {
		switch last.item.level {
		case levelFail:
			title = last.item.name + " is DOWN"
		case levelWarn:
			title = last.item.name + " is WARN"
		default:
			title = last.item.name + " recovered"
		}
		return title, priority, tags, lines, true
	}
	var parts []string
	for _, p := range []struct {
		n    int
		word string
	}{{down, "down"}, {warn, "warn"}, {up, "recovered"}} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.word))
		}
	}
	return strings.Join(parts, ", "), priority, tags, lines, true
}

// afterRound is called after every complete round.
func (a *alerter) afterRound(cfg config, snap snapshot) {
	if a.beat.key != cfg.HeartbeatURL {
		a.beat = channelState{key: cfg.HeartbeatURL}
	}
	if cfg.HeartbeatURL != "" {
		a.beat.result(a.now(), a.heartbeat(cfg.HeartbeatURL))
	}
	if k := ntfyKey(cfg); a.ntfy.key != k {
		a.ntfy = channelState{key: k}
	}
	if cfg.NtfyURL == "" {
		a.states = map[string]*alertState{}
		a.unsent = nil
		return
	}
	// A muted check is not judged at all, so its state stays as it was: when
	// the mute ends, one that is still down is reported after alert_after
	// rounds, one that came back in between sends nothing.
	items := alertItems(snap, cfg.AlertWarn)
	now := a.now()
	for i := range items {
		for _, n := range append([]string{items[i].name}, items[i].aliases...) {
			if n != "" && cfg.muted(n, now) {
				items[i].pending = true
			}
		}
	}
	changes := a.evaluate(items, cfg.AlertAfter)
	title, priority, tags, lines, ok := alertMessage(changes, cfg.alertRecovered())
	if !ok && len(a.unsent) == 0 {
		return
	}
	stamp := a.now().Format("15:04")
	for i := range lines {
		lines[i] = stamp + " " + lines[i]
	}
	body := lines
	if len(a.unsent) > 0 {
		if !ok {
			title, priority, tags = "Earlier alerts", "default", "hourglass"
		}
		body = append(append(body[:len(body):len(body)], "", "not sent earlier:"), a.unsent...)
	}
	for _, l := range lines {
		log.Printf("alert: %s", l)
	}
	err := a.send(cfg, title, priority, tags, strings.Join(body, "\n"))
	a.ntfy.result(a.now(), err)
	if err != nil {
		log.Printf("alert: sending to ntfy failed, will retry with the next message: %v", err)
		a.unsent = append(a.unsent, lines...)
		if len(a.unsent) > maxUnsent {
			a.unsent = a.unsent[len(a.unsent)-maxUnsent:]
		}
		return
	}
	a.unsent = nil
}

// send posts one message to ntfy (the client's timeout limits it).
func (a *alerter) send(cfg config, title, priority, tags, body string) error {
	req, err := http.NewRequest(http.MethodPost, cfg.NtfyURL, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", title)
	req.Header.Set("Priority", priority)
	req.Header.Set("Tags", tags)
	if cfg.NtfyToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.NtfyToken)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// testAlert sends a test notification (-test-alert) and returns the exit code.
func testAlert(cfg config) int {
	if cfg.NtfyURL == "" {
		fmt.Println("ntfy_url is not set in the config")
		return 1
	}
	host, _ := os.Hostname()
	err := newAlerter().send(cfg, "valesne test", "default", "wave",
		"Test notification from valesne "+appVersion()+" on "+host+". Alerts work.")
	if err != nil {
		fmt.Println("sending failed:", err)
		return 1
	}
	fmt.Println("sent to", maskSecretURL(cfg.NtfyURL))
	return 0
}

// heartbeat tells an outside service (e.g. healthchecks.io) that the app is
// alive; when these requests stop, that service alerts.
func (a *alerter) heartbeat(url string) error {
	resp, err := a.client.Get(url)
	if err != nil {
		log.Printf("heartbeat: %v", err)
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		log.Printf("heartbeat: HTTP %d", resp.StatusCode)
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
