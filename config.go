package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type config struct {
	ListenPort      int            `toml:"listen_port"`
	IntervalSeconds int            `toml:"interval_seconds"`
	StaggerMS       int            `toml:"stagger_ms"`
	TimeoutSeconds  int            `toml:"timeout_seconds"`
	DNSQuery        string         `toml:"dns_query"`
	HostsCheck      *bool          `toml:"hosts_check"`
	DNSCheck        *bool          `toml:"dns_check"`
	CertsCheck      *bool          `toml:"certs_check"`
	DockerCheck     *bool          `toml:"docker_check"`
	NtfyURL         string         `toml:"ntfy_url"`
	NtfyToken       string         `toml:"ntfy_token"`
	AlertAfter      int            `toml:"alert_after"`
	AlertRecovered  *bool          `toml:"alert_recovered"`
	AlertWarn       bool           `toml:"alert_warn"`
	HeartbeatURL    string         `toml:"heartbeat_url"`
	Mute            []string       `toml:"mute"`
	MuteUntil       string         `toml:"mute_until"`
	Targets         []target       `toml:"targets"`
	DNSServers      []dnsServer    `toml:"dns_servers"`
	Certs           []certTarget   `toml:"certs"`
	Docker          []dockerTarget `toml:"docker"`

	muteUntil time.Time // parsed MuteUntil (local time), zero = not set
}

// switchOn reads one of the *_check switches: a missing switch counts as on,
// so existing configs without it keep working.
func switchOn(b *bool) bool { return b == nil || *b }

// alertRecovered reports whether recoveries are sent too (default yes).
func (c config) alertRecovered() bool { return switchOn(c.AlertRecovered) }

// muteTimeFormat is the only accepted form of mute_until: date and time.
const muteTimeFormat = "2006-01-02 15:04"

// muteAll reports whether all alerts are muted at now: mute_until without a
// mute list, and not yet reached.
func (c config) muteAll(now time.Time) bool {
	return len(c.Mute) == 0 && !c.muteUntil.IsZero() && now.Before(c.muteUntil)
}

// mutedNames returns the names whose alerts are muted at now: the mute list,
// until mute_until when that is set; empty when it has passed.
func (c config) mutedNames(now time.Time) []string {
	if !c.muteUntil.IsZero() && !now.Before(c.muteUntil) {
		return nil
	}
	return c.Mute
}

// muted reports whether alerts for the check with this name are muted at now.
func (c config) muted(name string, now time.Time) bool {
	if c.muteAll(now) {
		return true
	}
	for _, m := range c.mutedNames(now) {
		if m == name {
			return true
		}
	}
	return false
}

// muteUntilText is mute_until for the page ("" when not set or passed).
func (c config) muteUntilText(now time.Time) string {
	if c.muteUntil.IsZero() || !now.Before(c.muteUntil) {
		return ""
	}
	return c.muteUntil.Format(muteTimeFormat)
}

// activeTargets, activeDNSServers, activeCerts and activeDocker return what
// to check: nothing when that check is turned off.
func (c config) activeTargets() []target {
	if !switchOn(c.HostsCheck) {
		return nil
	}
	return c.Targets
}

func (c config) activeDNSServers() []dnsServer {
	if !switchOn(c.DNSCheck) {
		return nil
	}
	return c.DNSServers
}

func (c config) activeCerts() []certTarget {
	if !switchOn(c.CertsCheck) {
		return nil
	}
	return c.Certs
}

func (c config) activeDocker() []dockerTarget {
	if !switchOn(c.DockerCheck) {
		return nil
	}
	return c.Docker
}

type target struct {
	Name     string `toml:"name"`
	URL      string `toml:"url"`
	Host     string `toml:"host"`
	OKStatus string `toml:"ok_status"`

	okRanges []statusRange // parsed OKStatus
}

const defaultOKStatus = "200-399"

// statusRange is an inclusive range of HTTP status codes, e.g. 200-399 or 401-401.
type statusRange struct{ from, to int }

// statusOK reports whether an HTTP status code counts as OK for this target.
func (t target) statusOK(code int) bool {
	for _, r := range t.okRanges {
		if code >= r.from && code <= r.to {
			return true
		}
	}
	return false
}

// parseOKStatus parses a list like "200-399,401" into ranges.
func parseOKStatus(s string) ([]statusRange, error) {
	var ranges []statusRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		from, err1 := strconv.Atoi(strings.TrimSpace(lo))
		to, err2 := from, error(nil)
		if isRange {
			to, err2 = strconv.Atoi(strings.TrimSpace(hi))
		}
		if err1 != nil || err2 != nil || from < 100 || to > 599 || from > to {
			return nil, fmt.Errorf("%q is not a status code (100-599) or a range like 200-399", part)
		}
		ranges = append(ranges, statusRange{from, to})
	}
	return ranges, nil
}

// settingDoc describes one general setting for the HELP page: an
// example (the value from defaultConfig, or a typical one) and what it does.
// The page shows no values of the running configuration: the app has no
// login, and what is checked is already on the STATUS page. The same
// explanations appear as comments in defaultConfig below.
type settingDoc struct {
	Key     string
	Example string
	Desc    string
}

// settingSection is one box of general settings on the HELP page.
type settingSection struct {
	Title    string
	Settings []settingDoc
}

var settingSections = []settingSection{
	{"GENERAL", []settingDoc{
		{"listen_port", "9090", "Port of the web page (http://localhost:<port>). A change takes effect only after the program is restarted."},
		{"interval_seconds", "60", "How often (in seconds) the round of all checks is repeated."},
		{"stagger_ms", "400", "Pause between individual checks in milliseconds, so the network is not hit by all checks at once."},
		{"timeout_seconds", "3", "How many seconds to wait for an answer before a check counts as failed."},
		{"dns_query", `"."`, `Name sent to DNS servers that have no "query" of their own. "." means the root zone, which every DNS server can answer.`},
	}},
	{"CHECKS ON / OFF", []settingDoc{
		{"hosts_check", "true", "Turns the host check (ping + HTTP) on or off. When off, the targets list is ignored and the HOSTS section is not shown. A missing switch counts as on (the same for all four)."},
		{"dns_check", "true", "Turns the DNS server check on or off. When off, the dns_servers list is ignored and the DNS SERVERS section is not shown."},
		{"certs_check", "true", "Turns the certificate check on or off. When off, the certs list is ignored and the CERTIFICATES section is not shown."},
		{"docker_check", "false", "Turns the Docker check on or off. When off, the [[docker]] blocks are ignored and the DOCKER section is not shown."},
	}},
	{"ALERTS", []settingDoc{
		{"ntfy_url", `"https://ntfy.sh/my-checker-k7x2p9q4"`, `ntfy topic that alerts are sent to (empty = no alerts). Install the ntfy app and subscribe to a topic with a long random name: anyone who knows the name can read it, so treat it like a password. Only changes are sent ("Router is DOWN", later "Router recovered after 12m"), all changes of one round in one message. Test it with "valesne -test-alert" (sends a test message and exits; in Docker "docker compose exec valesne /valesne -test-alert -config /config/config.toml").`},
		{"ntfy_token", `""`, "Access token for a protected ntfy topic (optional)."},
		{"alert_after", "3", "How many rounds in a row a change must be seen before it is sent (also for recoveries), so a single lost ping does not alert."},
		{"alert_recovered", "true", `Also send a message when a check is OK again ("recovered after 12m").`},
		{"alert_warn", "false", "Also alert on WARN (e.g. a DNS server answering REFUSED, an unhealthy container). FAIL always alerts, and a certificate WARN (renewal overdue) always alerts too; an unreachable or invalid certificate never does."},
		{"heartbeat_url", `"https://hc-ping.com/<uuid>"`, "URL requested (GET) after every round, e.g. a free healthchecks.io check, which alerts when the requests stop, i.e. when this server or valesne is down (empty = off)."},
		{"mute", `["Cloudflare", "web"]`, "Names of checks as shown on the status page (host, DNS server, certificate, Docker daemon or container; for a container its compose service name works too) whose alerts are muted, e.g. during maintenance. They are still checked and shown. Without mute_until: until removed."},
		{"mute_until", `"2026-09-27 18:00"`, "Date and time (local time, always with a time) until which alerts are muted: the checks in mute, or all alerts when mute is empty. A check still down when the mute ends is reported after alert_after rounds; one that came back sends nothing. After that time the setting has no effect."},
	}},
}

// defaultConfig is written on first start when the config file does not exist.
const defaultConfig = `# valesne configuration
#
# The program picks up changes to this file automatically within a few
# seconds; no restart is needed (except for listen_port). If the file contains
# an error, the program keeps running with the last valid configuration and
# shows the error on the STATUS page. Lines starting with # are comments.
#
# The checks below are examples with public services (example.com, the
# Cloudflare and Quad9 DNS resolvers), so every kind of check can be seen
# right away. Replace them with your own hosts, DNS servers and
# certificates. The HELP page explains every setting.

# Port of the web page (http://localhost:9090).
# A change takes effect only after the program is restarted.
listen_port = 9090

# How often (in seconds) the round of all checks is repeated.
interval_seconds = 60

# Pause between individual checks in milliseconds, so the network is not hit
# by all checks at once.
stagger_ms = 400

# How many seconds to wait for an answer before a check counts as failed.
timeout_seconds = 3

# Name sent to DNS servers that have no "query" of their own.
# "." means the root zone, which every DNS server can answer.
dns_query = "."

# Turn each kind of check on or off (true/false). When a check is off, its
# list below is ignored and its section is not shown on the page. A missing
# switch counts as on.
hosts_check  = true    # targets: ping + HTTP
dns_check    = true    # dns_servers
certs_check  = true    # certs
docker_check = false   # the [[docker]] block at the end of this file

# ---------------------------------------------------------------------------
# Alerts: push notifications to your phone through ntfy (https://ntfy.sh).
# Install the ntfy app, subscribe to a topic with a long random name (anyone
# who knows the name can read it, so treat it like a password) and put its
# URL here. Empty = no alerts.
#
# Only changes are sent: "Router is DOWN", later "Router recovered after 12m",
# nothing in between. All changes of one round go into one message. Nothing
# is sent on startup or a config reload for checks that are fine.
# FAIL always alerts; WARN only for certificates (renewal overdue), or for
# everything with alert_warn = true. Never alerted: a stopped container
# that is not monitored, and a certificate that cannot be reached or is not
# valid (only its expiry alerts).
#
# Test it: "valesne -test-alert" sends a test message and exits (in Docker:
# docker compose exec valesne /valesne -test-alert -config /config/config.toml).
# ---------------------------------------------------------------------------

ntfy_url        = ""      # e.g. "https://ntfy.sh/my-checker-k7x2p9q4"
ntfy_token      = ""      # access token for a protected topic (optional)
alert_after     = 3       # rounds in a row before a change is sent
alert_recovered = true    # also send "recovered"
alert_warn      = false   # also alert on WARN (not only FAIL)

# URL requested after every round, e.g. a free healthchecks.io check
# ("https://hc-ping.com/<uuid>"). When the requests stop (this server or
# valesne is down, so no alert can be sent from here), healthchecks.io
# alerts you. Empty = off.
heartbeat_url = ""

# Mute alerts, e.g. during maintenance (checks still run and are shown):
#   mute        names of checks as shown on the page (host, DNS server,
#               certificate, Docker daemon or container; for a container its
#               compose service name works too, e.g. "web")
#   mute_until  "YYYY-MM-DD HH:MM" local time, always with a time
# Only mute: these are muted until you remove them. Only mute_until: ALL
# alerts are muted until then. Both: these are muted until then. After
# mute_until it has no effect. A check still down when the mute ends is
# reported after alert_after rounds; one that came back sends nothing.
mute       = []       # e.g. ["Cloudflare", "web"]
mute_until = ""       # e.g. "2026-09-27 18:00"

# ---------------------------------------------------------------------------
# Hosts and applications to check: one line per host in the list below
# (a [[targets]] block per host works too, but not both for the same list).
#
#   name       name shown on the page (optional, defaults to host)
#   url        application address for the HTTP check (optional; no url = no HTTP check)
#   host       name or IP for the ping check (optional when url is set)
#   ok_status  HTTP status codes that count as OK (optional, default "200-399"),
#              a list of codes and ranges, e.g. "200-399,401"
#
# Each host gets a ping and an HTTP check (when url is set). The name is
# resolved by the system resolver; when that fails, ping shows "DNS: ...".
# By default an HTTP response of 200-399 counts as OK.
# A page that needs a login often answers 401 (or 403): add that code to
# ok_status when you only want to know that the web server is up.
# ---------------------------------------------------------------------------

targets = [
  { name = "Example",    url  = "https://example.com" },   # ping + HTTP
  { name = "Cloudflare", host = "1.1.1.1" },               # ping only
  # { name = "Behind a login", url = "https://intranet.example.com/app/", ok_status = "200-399,401" },
]

# ---------------------------------------------------------------------------
# DNS servers queried directly (bypassing the system resolver): one line per
# server in the list below (or a [[dns_servers]] block per server).
#
#   name    name shown on the page (optional, defaults to server)
#   server  server IP, optionally with a port (default 53), e.g. "10.0.0.1:53"
#   query   name to ask for (optional, defaults to dns_query above)
#
# OK   = the server answered (NOERROR or NXDOMAIN)
# WARN = the server answered with an error (REFUSED, SERVFAIL ...)
# FAIL = no answer
# ---------------------------------------------------------------------------

dns_servers = [
  { name = "Cloudflare DNS", server = "1.1.1.1" },
  { name = "Quad9",          server = "9.9.9.9", query = "example.com" },   # own query
  # { name = "Internal DNS", server = "10.0.0.10", query = "intranet.company.local" },
]

# ---------------------------------------------------------------------------
# TLS certificates, e.g. to notice in time when certbot stops renewing: one
# line per certificate in the list below (or a [[certs]] block per
# certificate). The certificate that is actually
# served on the address is checked (so a missing nginx reload after a
# renewal is noticed too).
#
#   name     name shown on the page (optional, defaults to host)
#   host     name on the certificate, used for SNI and verification,
#            e.g. "example.com" (no https://, no port)
#   address  where to connect, "host:port" or "IP:port" (optional, defaults
#            to host:443). Behind Cloudflare or another proxy, set the origin
#            here (e.g. "192.168.1.10:443"), otherwise you see the proxy's
#            certificate instead of your own.
#
# OK   = enough time left
# WARN = less than 1/4 of the lifetime left (certbot renews at about 1/3, so
#        the renewal is overdue), at most 30 days before expiry (so a 1-year
#        certificate warns at 30 days, not 99); the certificate still works
# FAIL = fewer than 7 days left, or expired
# Not reachable (e.g. connection refused, no TLS on the port) or not valid
# (hostname, chain, self-signed): WARN with the error, but never alerts;
# only the expiry does. Whether the server is up is for the host checks.
# ---------------------------------------------------------------------------

certs = [
  { name = "Example", host = "example.com" },
  # { name = "My site", host = "my-site.example", address = "192.168.1.10:443" },   # origin behind a proxy
]

# ---------------------------------------------------------------------------
# Docker daemons on this server. Each [[docker]] block is one daemon. The
# block below is off (docker_check = false at the top): set docker_check =
# true to use it; in docker compose it works as it is (DOCKER_HOST points to
# the read-only socket proxy).
#
#   name        name shown on the page (optional, defaults to endpoint)
#   endpoint    "unix:///var/run/docker.sock" or "tcp://host:2375" (optional;
#               defaults to DOCKER_HOST when set, e.g. by docker-compose.yml,
#               otherwise unix:///var/run/docker.sock)
#   monitored   the containers that must be running (container or compose
#               service name, optional). Every container on the daemon is
#               shown, running and stopped; a monitored one that is stopped
#               or gone (docker compose down) is FAIL and alerts.
#
# The user valesne runs as needs access to the Docker socket (member of
# the "docker" group, or root). Only read-only requests are sent.
#
# Daemon:    OK = answers, FAIL = not reachable
# Container: OK = running (and healthy), WAIT = health check still starting,
#            WARN = unhealthy or restarting, STOPPED = exited, FAIL = missing
#            or dead. A STOPPED container counts as DOWN only when it is
#            monitored; otherwise it is just shown. Monitored containers are listed first, tagged [MONITORED].
# ---------------------------------------------------------------------------

[[docker]]
name = "Docker"
# endpoint  = "unix:///var/run/docker.sock"   # optional, see above
# monitored = ["web", "db"]                   # these must run (alert)
`

// ensureConfigFile creates the default configuration when the file does not exist.
func ensureConfigFile(path string) error {
	_, err := os.Stat(path)
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.WriteFile(path, []byte(defaultConfig), 0o644); err != nil {
		return err
	}
	log.Printf("config: %s did not exist, created a default file with examples - edit it", path)
	return nil
}

func loadConfig(path string) (config, error) {
	var cfg config
	meta, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return config{}, err
	}
	// An unknown key is almost always a typo (e.g. "intervall_seconds") that
	// would otherwise be silently ignored.
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		sort.Strings(keys)
		return config{}, fmt.Errorf("unknown settings: %s", strings.Join(keys, ", "))
	}

	if cfg.ListenPort <= 0 {
		cfg.ListenPort = 9090
	}
	if cfg.IntervalSeconds < 1 {
		cfg.IntervalSeconds = 60
	}
	if cfg.StaggerMS < 0 {
		cfg.StaggerMS = 0
	}
	if cfg.TimeoutSeconds < 1 {
		cfg.TimeoutSeconds = 3
	}
	if len(cfg.activeTargets()) == 0 && len(cfg.activeDNSServers()) == 0 && len(cfg.activeCerts()) == 0 && len(cfg.activeDocker()) == 0 {
		return config{}, errors.New("nothing to check: targets, dns_servers, certs and [[docker]] are all empty or turned off")
	}
	for i := range cfg.Targets {
		t := &cfg.Targets[i]
		t.URL = strings.TrimSpace(t.URL)
		if t.URL != "" {
			t.URL = normalizeURL(t.URL)
		}
		t.Host = strings.TrimSpace(t.Host)
		if t.Host == "" {
			t.Host = hostFromURL(t.URL)
		}
		if t.Host == "" {
			return config{}, fmt.Errorf("targets #%d: host or url is missing", i+1)
		}
		if t.Name == "" {
			t.Name = t.Host
		}
		t.OKStatus = strings.TrimSpace(t.OKStatus)
		if t.OKStatus == "" {
			t.OKStatus = defaultOKStatus
		}
		ranges, err := parseOKStatus(t.OKStatus)
		if err != nil {
			return config{}, fmt.Errorf("targets #%d: ok_status: %v", i+1, err)
		}
		t.okRanges = ranges
	}
	cfg.NtfyURL = strings.TrimSpace(cfg.NtfyURL)
	cfg.NtfyToken = strings.TrimSpace(cfg.NtfyToken)
	cfg.HeartbeatURL = strings.TrimSpace(cfg.HeartbeatURL)
	for _, u := range []struct{ key, val string }{{"ntfy_url", cfg.NtfyURL}, {"heartbeat_url", cfg.HeartbeatURL}} {
		if u.val != "" && !strings.HasPrefix(u.val, "https://") && !strings.HasPrefix(u.val, "http://") {
			return config{}, fmt.Errorf("%s must start with https:// or http://", u.key)
		}
	}
	if cfg.AlertAfter < 1 {
		cfg.AlertAfter = 3
	}
	cfg.MuteUntil = strings.TrimSpace(cfg.MuteUntil)
	if cfg.MuteUntil != "" {
		t, err := time.ParseInLocation(muteTimeFormat, cfg.MuteUntil, time.Local)
		if err != nil {
			return config{}, fmt.Errorf(`mute_until must be a date and time like "2026-09-27 18:00" (local time), got %q`, cfg.MuteUntil)
		}
		cfg.muteUntil = t
	}
	for i, m := range cfg.Mute {
		cfg.Mute[i] = strings.TrimSpace(m)
	}
	cfg.DNSQuery = strings.TrimSpace(cfg.DNSQuery)
	if cfg.DNSQuery == "" {
		cfg.DNSQuery = defaultDNSQuery
	}
	for i := range cfg.DNSServers {
		d := &cfg.DNSServers[i]
		if strings.TrimSpace(d.Server) == "" {
			return config{}, fmt.Errorf("dns_servers #%d: server is missing", i+1)
		}
		d.Server = withDefaultPort(d.Server, "53")
		d.Query = strings.TrimSpace(d.Query)
		if d.Query == "" {
			d.Query = cfg.DNSQuery
		}
		if d.Name == "" {
			d.Name = d.Server
		}
	}
	for i := range cfg.Certs {
		t := &cfg.Certs[i]
		t.Host = strings.TrimSpace(t.Host)
		if t.Host == "" {
			return config{}, fmt.Errorf("certs #%d: host is missing", i+1)
		}
		if strings.Contains(t.Host, "/") || strings.Contains(t.Host, ":") {
			return config{}, fmt.Errorf("certs #%d: host must be a plain name like \"example.com\" (no https://, no port; the port goes into address)", i+1)
		}
		t.Address = strings.TrimSpace(t.Address)
		if t.Address == "" {
			t.Address = t.Host
		}
		t.Address = withDefaultPort(t.Address, "443")
		if t.Name == "" {
			t.Name = t.Host
		}
	}
	for i := range cfg.Docker {
		d := &cfg.Docker[i]
		d.Endpoint = strings.TrimSpace(d.Endpoint)
		if d.Endpoint == "" {
			d.Endpoint = dockerEndpointDefault()
		}
		if !strings.HasPrefix(d.Endpoint, "unix://") && !strings.HasPrefix(d.Endpoint, "tcp://") {
			return config{}, fmt.Errorf("docker #%d: endpoint must start with unix:// or tcp://", i+1)
		}
		if d.Name == "" {
			d.Name = d.Endpoint
		}
		for j, c := range d.Monitored {
			d.Monitored[j] = strings.TrimSpace(c)
			if d.Monitored[j] == "" {
				return config{}, fmt.Errorf("docker #%d: monitored contains an empty name", i+1)
			}
		}
	}
	return cfg, nil
}

// watchConfig checks every 2 s whether the file has changed and reloads it.
// Polling instead of file system notifications, because those do not work
// reliably on every system and on network/mounted folders.
func watchConfig(path string, st *store) {
	stamp := func() (time.Time, int64, error) {
		fi, err := os.Stat(path)
		if err != nil {
			return time.Time{}, 0, err
		}
		return fi.ModTime(), fi.Size(), nil
	}
	lastMod, lastSize, _ := stamp()

	for range time.Tick(2 * time.Second) {
		mod, size, err := stamp()
		if err != nil {
			st.setConfigError(err.Error())
			continue
		}
		if mod.Equal(lastMod) && size == lastSize {
			continue
		}
		lastMod, lastSize = mod, size

		cfg, err := loadConfig(path)
		if err != nil {
			log.Printf("config: error, keeping the last valid configuration: %v", err)
			st.setConfigError(err.Error())
			continue
		}
		log.Printf("config: reloaded (hosts %d, DNS servers %d, certificates %d, Docker daemons %d)", len(cfg.activeTargets()), len(cfg.activeDNSServers()), len(cfg.activeCerts()), len(cfg.activeDocker()))
		st.apply(cfg)
	}
}

// hostFromURL returns the host of a URL from normalizeURL (with a scheme).
func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// normalizeURL adds http:// when the URL has no scheme (raw is trimmed).
func normalizeURL(raw string) string {
	if raw == "" || strings.Contains(raw, "://") {
		return raw
	}
	return "http://" + raw
}

// withDefaultPort adds port to a host or IP address that has none (s is
// trimmed; an IPv6 address may be given with or without brackets).
func withDefaultPort(s, port string) string {
	s = strings.TrimSpace(s)
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(strings.Trim(s, "[]"), port)
}

// maskSecretURL shows only the scheme, host and the first characters of the
// path of a URL whose path is a secret (ntfy topic, healthchecks.io UUID),
// e.g. in the output of -test-alert.
func maskSecretURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(set)"
	}
	path := strings.TrimPrefix(u.Path, "/")
	if len(path) > 4 {
		path = path[:4] + "…"
	}
	return u.Scheme + "://" + u.Host + "/" + path
}
