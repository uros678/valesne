package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

//go:embed web
var webFS embed.FS

var pages = template.Must(template.ParseFS(webFS, "web/*.html"))

type probe struct {
	OK         bool     `json:"ok"`
	Pending    bool     `json:"pending"`
	StatusCode int      `json:"statusCode,omitempty"`
	Detail     string   `json:"detail,omitempty"`
	LatencyMS  int64    `json:"latencyMs"`
	Error      string   `json:"error,omitempty"`
	CheckedAt  string   `json:"checkedAt,omitempty"`
	Skipped    bool     `json:"skipped,omitempty"`
	Warn       bool     `json:"warn,omitempty"`
	Stopped    bool     `json:"stopped,omitempty"` // container exited or never started
	History    []sample `json:"history,omitempty"`
}

// sample is one measurement in the history the UI draws the latency graph from.
type sample struct {
	LatencyMS int64 `json:"ms"`
	OK        bool  `json:"ok"`
	Warn      bool  `json:"warn,omitempty"`
}

const historySize = 40

// withHistory returns p with the history from prev, extended by measurement p.
// Only hosts and DNS servers keep a history: the other boxes draw no graph.
// It always allocates a new slice, because snapshot shares slices with readers
// outside the lock.
func withHistory(prev, p probe) probe {
	h := prev.History
	if len(h) >= historySize {
		h = h[len(h)-historySize+1:]
	}
	p.History = make([]sample, len(h), len(h)+1)
	copy(p.History, h)
	p.History = append(p.History, sample{LatencyMS: p.LatencyMS, OK: p.OK, Warn: p.Warn})
	return p
}

type hostResult struct {
	Name    string `json:"name"`
	Host    string `json:"host"`
	URL     string `json:"url,omitempty"`
	OK      bool   `json:"ok"`
	Pending bool   `json:"pending"`
	Ping    probe  `json:"ping"`
	HTTP    probe  `json:"http"`
}

func (r hostResult) key() string { return r.Name + "|" + r.Host + "|" + r.URL }

type dnsServerResult struct {
	Name   string `json:"name"`
	Server string `json:"server"`
	Query  string `json:"query"`
	Probe  probe  `json:"probe"`
}

func (d dnsServerResult) key() string { return d.Name + "|" + d.Server + "|" + d.Query }

type certResult struct {
	Name    string `json:"name"`
	Host    string `json:"host"`
	Address string `json:"address"`
	certCheck
}

func (c certResult) key() string { return c.Name + "|" + c.Host + "|" + c.Address }

type dockerResult struct {
	Name     string   `json:"name"`
	Endpoint string   `json:"endpoint"`
	Host     string   `json:"host,omitempty"` // last known "hostname · OS" from /info
	Info     string   `json:"info,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Probe    probe    `json:"probe"`
	// Containers: every container on the daemon; a stopped one counts as DOWN
	// only when it is monitored.
	Containers []containerResult `json:"containers"`
}

func (d dockerResult) key() string { return d.Name + "|" + d.Endpoint }

type containerResult struct {
	Name      string `json:"name"`                // as written in the config, or the container name
	Monitored bool   `json:"monitored,omitempty"` // must run: stopped or missing is FAIL
	// MonitorName is the configured name a monitored container was found by
	// (e.g. "web" for "home-web-1"): its identity for alerting,
	// the same whether it runs, is stopped or is gone.
	MonitorName  string `json:"-"`
	Container    string `json:"container,omitempty"` // actual container name
	Service      string `json:"service,omitempty"`   // compose service name
	Image        string `json:"image,omitempty"`
	ID           string `json:"-"`
	RestartCount int    `json:"restartCount"`
	Uptime       string `json:"uptime,omitempty"`
	Probe        probe  `json:"probe"`
}

// idle reports whether c is a stopped container that is not monitored: it
// is only shown (amber STOPPED), never counted as DOWN and never alerted.
// setDocker marks its probe Warn, which is what the page goes by.
func (c containerResult) idle() bool { return c.Probe.Stopped && !c.Monitored }

type snapshot struct {
	Version         string            `json:"version"`
	IntervalSeconds int               `json:"intervalSeconds"`
	StaggerMS       int               `json:"staggerMs"`
	Up              int               `json:"up"`
	Down            int               `json:"down"`
	Warn            int               `json:"warn"`
	Pending         int               `json:"pending"`
	Stopped         int               `json:"stopped"` // stopped containers that are not monitored; not DOWN
	ConfigError     string            `json:"configError,omitempty"`
	ConfigErrorAt   string            `json:"configErrorAt,omitempty"` // "2026-09-28 10:15:00"
	ListenPort      int               `json:"listenPort"`              // the port the app listens on
	RestartPort     int               `json:"restartPort,omitempty"`   // a changed listen_port, used after a restart
	MuteAll         bool              `json:"muteAll,omitempty"`       // all alerts muted (mute_until without mute)
	Muted           []string          `json:"muted,omitempty"`         // names of muted checks
	MuteUntil       string            `json:"muteUntil,omitempty"`     // "2026-09-27 18:00" while it applies
	Alerts          alertStatus       `json:"alerts"`                  // ntfy and heartbeat, not counted in the summary
	Results         []hostResult      `json:"results"`
	DNSServers      []dnsServerResult `json:"dnsServers"`
	Certs           []certResult      `json:"certs"`
	Docker          []dockerResult    `json:"docker"`
}

// store holds the current configuration and the results. Every new
// configuration increments gen; check results from a previous generation are
// discarded, because the indexes no longer match.
type store struct {
	mu       sync.RWMutex
	cfg      config
	gen      int
	port     int // listen_port of the first config: a changed one needs a restart
	loadedAt time.Time
	cfgErr   string
	cfgErrAt time.Time
	results  []hostResult
	servers  []dnsServerResult
	certs    []certResult
	docker   []dockerResult
	alerts   alerterState // copied from the alerter after every round
	changed  chan struct{}
}

func newStore(cfg config) *store {
	s := &store{changed: make(chan struct{}, 1), port: cfg.ListenPort}
	s.apply(cfg)
	<-s.changed // the initial configuration is not a "change"
	return s
}

// apply replaces the configuration. Hosts and servers that did not change
// keep their results and history.
func (s *store) apply(cfg config) {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldHosts := map[string]hostResult{}
	for _, r := range s.results {
		oldHosts[r.key()] = r
	}
	oldServers := map[string]dnsServerResult{}
	for _, d := range s.servers {
		oldServers[d.key()] = d
	}
	oldDocker := map[string]dockerResult{}
	for _, d := range s.docker {
		oldDocker[d.key()] = d
	}

	s.results = make([]hostResult, len(cfg.activeTargets()))
	for i, t := range cfg.activeTargets() {
		httpProbe := probe{Pending: true}
		if t.URL == "" {
			httpProbe = probe{Skipped: true}
		}
		r := hostResult{
			Name:    t.Name,
			Host:    t.Host,
			URL:     t.URL,
			Pending: true,
			Ping:    probe{Pending: true},
			HTTP:    httpProbe,
		}
		if old, ok := oldHosts[r.key()]; ok {
			r = old
		}
		s.results[i] = r
	}
	s.servers = make([]dnsServerResult, len(cfg.activeDNSServers()))
	for i, d := range cfg.activeDNSServers() {
		r := dnsServerResult{
			Name:   d.Name,
			Server: d.Server,
			Query:  d.Query,
			Probe:  probe{Pending: true},
		}
		if old, ok := oldServers[r.key()]; ok {
			r = old
		}
		s.servers[i] = r
	}
	oldCerts := map[string]certResult{}
	for _, c := range s.certs {
		oldCerts[c.key()] = c
	}
	s.certs = make([]certResult, len(cfg.activeCerts()))
	for i, c := range cfg.activeCerts() {
		r := certResult{Name: c.Name, Host: c.Host, Address: c.Address, certCheck: certCheck{Probe: probe{Pending: true}}}
		if old, ok := oldCerts[r.key()]; ok {
			r = old
		}
		s.certs[i] = r
	}
	s.docker = make([]dockerResult, len(cfg.activeDocker()))
	for i, d := range cfg.activeDocker() {
		r := dockerResult{Name: d.Name, Endpoint: d.Endpoint, Probe: probe{Pending: true}}
		if old, ok := oldDocker[r.key()]; ok {
			// The container list comes from the daemon; keep the last one until
			// the next round.
			r.Host, r.Info, r.Warnings, r.Probe, r.Containers = old.Host, old.Info, old.Warnings, old.Probe, old.Containers
		}
		s.docker[i] = r
	}

	s.cfg = cfg
	s.gen++
	s.loadedAt = time.Now()
	s.cfgErr = ""
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

func (s *store) setAlerts(a alerterState) {
	s.mu.Lock()
	s.alerts = a
	s.mu.Unlock()
}

func (s *store) setConfigError(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfgErr != msg {
		s.cfgErr = msg
		s.cfgErrAt = time.Now()
	}
}

func (s *store) current() (config, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg, s.gen
}

// pause waits for d, but returns immediately (false) when a new configuration arrives.
func (s *store) pause(d time.Duration) bool {
	if d <= 0 {
		select {
		case <-s.changed:
			return false
		default:
			return true
		}
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-s.changed:
		return false
	case <-t.C:
		return true
	}
}

func (s *store) setPing(gen, i int, p probe) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if gen != s.gen {
		return
	}
	s.results[i].Ping = withHistory(s.results[i].Ping, p)
	s.results[i].refresh()
}

func (s *store) setHTTP(gen, i int, p probe) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if gen != s.gen {
		return
	}
	s.results[i].HTTP = withHistory(s.results[i].HTTP, p)
	s.results[i].refresh()
}

func (s *store) setServer(gen, i int, p probe) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if gen != s.gen {
		return
	}
	s.servers[i].Probe = withHistory(s.servers[i].Probe, p)
}

func (s *store) setCert(gen, i int, res certCheck) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if gen != s.gen {
		return
	}
	s.certs[i].certCheck = res
}

func (s *store) setDocker(gen, i int, res dockerCheck) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if gen != s.gen {
		return
	}
	old := s.docker[i]
	d := old
	d.Probe = res.Daemon
	if res.Host != "" {
		// Kept while the daemon is unreachable, so the page still says which host it is.
		d.Host = res.Host
	}
	d.Info = res.Info
	d.Warnings = res.Warnings
	checks := res.Containers
	if res.ContainerError != "" {
		// Nothing is known about the containers: mark the known ones failed and
		// keep their last known identity.
		checks = make([]containerResult, len(old.Containers))
		for j, prev := range old.Containers {
			prev.Uptime = ""
			prev.Probe = probe{CheckedAt: res.Daemon.CheckedAt, Error: res.ContainerError}
			checks[j] = prev
		}
	}
	prevByName := map[string]containerResult{}
	for _, c := range old.Containers {
		prevByName[c.Name] = c
	}
	// A new slice, because snapshots taken earlier still share the old one.
	d.Containers = make([]containerResult, len(checks))
	for j, c := range checks {
		prev := prevByName[c.Name]
		if c.idle() {
			// A stopped container that is not monitored is shown, not an error.
			c.Probe.Warn = true
		}
		// A running container whose restart count went up since the last round
		// has crashed and been restarted in between (restart loop).
		if c.Probe.OK && prev.ID == c.ID && c.RestartCount > prev.RestartCount {
			c.Probe.OK = false
			c.Probe.Warn = true
			c.Probe.Error = fmt.Sprintf("restarted %d× since last check", c.RestartCount-prev.RestartCount)
		}
		d.Containers[j] = c
	}
	s.docker[i] = d
}

func (r *hostResult) refresh() {
	r.Pending = r.Ping.Pending || (!r.HTTP.Skipped && r.HTTP.Pending)
	r.OK = !r.Pending && r.Ping.OK && (r.HTTP.Skipped || r.HTTP.OK)
}

func (s *store) snapshot() snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	out := snapshot{
		Version:         appVersion(),
		IntervalSeconds: s.cfg.IntervalSeconds,
		StaggerMS:       s.cfg.StaggerMS,
		ConfigError:     s.cfgErr,
		ListenPort:      s.port,
		MuteAll:         s.cfg.muteAll(now),
		Muted:           s.cfg.mutedNames(now),
		MuteUntil:       s.cfg.muteUntilText(now),
		Alerts:          s.alerts.status(s.cfg, now),
		Results:         make([]hostResult, len(s.results)),
		DNSServers:      make([]dnsServerResult, len(s.servers)),
		Certs:           make([]certResult, len(s.certs)),
	}
	if s.cfg.ListenPort != s.port {
		out.RestartPort = s.cfg.ListenPort
	}
	if s.cfgErr != "" {
		out.ConfigErrorAt = s.cfgErrAt.Format("2006-01-02 15:04:05")
	}
	copy(out.Results, s.results)
	copy(out.DNSServers, s.servers)
	copy(out.Certs, s.certs)
	out.Docker = make([]dockerResult, len(s.docker))
	copy(out.Docker, s.docker)
	// Everything counts in one summary: UP, WARN (e.g. a certificate whose
	// server is unreachable, an unhealthy container), DOWN, WAIT.
	count := func(pending, ok, warn bool) {
		switch {
		case pending:
			out.Pending++
		case ok:
			out.Up++
		case warn:
			out.Warn++
		default:
			out.Down++
		}
	}
	probeWarn := func(p probe) bool { return p.Warn && !p.Stopped }
	for _, r := range out.Results {
		// A host is WARN when none of its checks failed but one warned.
		fail := (!r.Ping.OK && !probeWarn(r.Ping)) || (!r.HTTP.Skipped && !r.HTTP.OK && !probeWarn(r.HTTP))
		count(r.Pending, r.OK, !fail)
	}
	for _, d := range out.DNSServers {
		count(d.Probe.Pending, d.Probe.OK, probeWarn(d.Probe))
	}
	for _, c := range out.Certs {
		count(c.Probe.Pending, c.Probe.OK, probeWarn(c.Probe))
	}
	for _, d := range out.Docker {
		count(d.Probe.Pending, d.Probe.OK, probeWarn(d.Probe))
		for _, c := range d.Containers {
			if c.idle() {
				out.Stopped++
				continue
			}
			count(c.Probe.Pending, c.Probe.OK, probeWarn(c.Probe))
		}
	}
	return out
}

func checkHTTP(t target, timeout time.Duration) probe {
	p := probe{CheckedAt: time.Now().Format(time.RFC3339)}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL, nil)
	if err != nil {
		p.Error = err.Error()
		return p
	}

	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	p.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		p.Error = shortNetError(err)
		return p
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	p.StatusCode = resp.StatusCode
	p.Detail = strconv.Itoa(resp.StatusCode)
	p.OK = t.statusOK(resp.StatusCode)
	if !p.OK {
		p.Error = fmt.Sprintf("HTTP %d (ok_status %s)", resp.StatusCode, t.OKStatus)
	}
	return p
}

// runChecks runs rounds of checks in an endless loop. A new configuration
// interrupts the current round and starts a new one right away. Alerts are
// only worked out after a complete round.
func runChecks(st *store, al *alerter) {
	for {
		cfg, gen := st.current()
		interval := time.Duration(cfg.IntervalSeconds) * time.Second
		roundStart := time.Now()
		if !runRound(st, cfg, gen) {
			continue
		}
		al.afterRound(cfg, st.snapshot())
		st.setAlerts(al.state())
		st.pause(interval - time.Since(roundStart))
	}
}

// runRound returns false when it was interrupted by a new configuration.
func runRound(st *store, cfg config, gen int) bool {
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	stagger := time.Duration(cfg.StaggerMS) * time.Millisecond

	first := true
	next := func() bool {
		if first {
			first = false
			return st.pause(0)
		}
		return st.pause(stagger)
	}

	for i, t := range cfg.activeTargets() {
		if !next() {
			return false
		}
		st.setPing(gen, i, checkPing(t.Host, timeout))
		if t.URL == "" {
			continue
		}
		if !next() {
			return false
		}
		st.setHTTP(gen, i, checkHTTP(t, timeout))
	}
	for i, d := range cfg.activeDNSServers() {
		if !next() {
			return false
		}
		st.setServer(gen, i, checkDNSServer(d.Server, d.Query, timeout))
	}
	for i, c := range cfg.activeCerts() {
		if !next() {
			return false
		}
		st.setCert(gen, i, checkCert(c, timeout))
	}
	for i, d := range cfg.activeDocker() {
		if !next() {
			return false
		}
		st.setDocker(gen, i, checkDocker(d, timeout))
	}
	return true
}

type pageData struct {
	Title      string
	Page       string
	Version    string // only set for the HELP page
	ConfigPath string // only set for the STATUS page (config error box)
}

// helpData is what the HELP page shows: about the app (version, config
// file), the documentation of every setting and the license, but no values
// of the running configuration (no login; what is checked is on the STATUS
// page). Config errors and a changed listen_port are shown on the STATUS
// page only.
type helpData struct {
	pageData
	Path     string
	LoadedAt string
	Sections []settingSection
}

func (s *store) help(path string) helpData {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return helpData{
		pageData: pageData{Title: "valesne · help", Page: "help", Version: appVersion()},
		Path:     path,
		LoadedAt: s.loadedAt.Format("2006-01-02 15:04:05"),
		Sections: settingSections,
	}
}

func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("template %s: %v", name, err)
	}
}

// healthcheck asks the running app on this machine whether it is alive and
// returns the exit code for the Docker HEALTHCHECK (0 = healthy). The port is
// taken from the config; if it cannot be read, the default 9090 is used.
func healthcheck(path string) int {
	port := 9090
	if cfg, err := loadConfig(path); err == nil {
		port = cfg.ListenPort
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: HTTP", resp.StatusCode)
		return 1
	}
	return 0
}

func main() {
	configPath := flag.String("config", "config.toml", "path to the configuration file")
	healthcheckFlag := flag.Bool("healthcheck", false, "check that the app running on this machine answers on /healthz and exit (0 = healthy); for the Docker HEALTHCHECK")
	versionFlag := flag.Bool("version", false, "print the version and exit")
	testAlertFlag := flag.Bool("test-alert", false, "send a test notification to ntfy_url from the config and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Println("valesne", appVersion())
		return
	}

	path, err := filepath.Abs(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *healthcheckFlag {
		os.Exit(healthcheck(path))
	}
	if err := ensureConfigFile(path); err != nil {
		log.Fatalf("config: %v", err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		log.Fatalf("config %s: %v", path, err)
	}
	if *testAlertFlag {
		os.Exit(testAlert(cfg))
	}

	st := newStore(cfg)
	go runChecks(st, newAlerter())
	go watchConfig(path, st)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		render(w, "status.html", pageData{Title: "valesne", Page: "status", ConfigPath: path})
	})
	mux.HandleFunc("/help", func(w http.ResponseWriter, r *http.Request) {
		render(w, "help.html", st.help(path))
	})
	mux.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, webFS, "web/style.css")
	})
	// /healthz only says that the app itself runs, not whether the checks are
	// OK: a monitored host being down must not make the container unhealthy.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		snap := st.snapshot()
		if snap.Down > 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		if err := json.NewEncoder(w).Encode(snap); err != nil {
			log.Printf("json: %v", err)
		}
	})

	addr := ":" + strconv.Itoa(cfg.ListenPort)
	log.Printf("valesne %s listening on %s, config %s", appVersion(), addr, path)
	log.Printf("interval %ds, stagger %dms, timeout %ds, hosts %d, DNS servers %d, certificates %d, Docker daemons %d",
		cfg.IntervalSeconds, cfg.StaggerMS, cfg.TimeoutSeconds, len(cfg.activeTargets()), len(cfg.activeDNSServers()), len(cfg.activeCerts()), len(cfg.activeDocker()))
	log.Fatal(http.ListenAndServe(addr, mux))
}
