package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
)

const defaultDockerEndpoint = "unix:///var/run/docker.sock"

// dockerEndpointDefault is used when a [[docker]] block has no endpoint: the
// standard DOCKER_HOST variable when it is a unix:// or tcp:// address (the
// compose file sets it to the socket proxy), otherwise the local socket.
func dockerEndpointDefault() string {
	if h := strings.TrimSpace(os.Getenv("DOCKER_HOST")); strings.HasPrefix(h, "unix://") || strings.HasPrefix(h, "tcp://") {
		return h
	}
	return defaultDockerEndpoint
}

// dockerTarget is a Docker daemon from the config.
type dockerTarget struct {
	Name     string `toml:"name"`
	Endpoint string `toml:"endpoint"`
	// Monitored: every container is shown; these must run, so stopped or
	// removed is FAIL and alerts.
	Monitored []string `toml:"monitored"`
}

// dockerClient talks to the Docker Engine API. It can only send GET
// requests, so valesne can never change anything on the daemon.
type dockerClient struct {
	http *http.Client
	base string
}

func newDockerClient(endpoint string, timeout time.Duration) (*dockerClient, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{DisableKeepAlives: true}
	c := &dockerClient{http: &http.Client{Transport: tr, Timeout: timeout}}
	switch u.Scheme {
	case "unix":
		socket := u.Path
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}
		c.base = "http://docker"
	case "tcp":
		c.base = "http://" + u.Host
	default:
		return nil, fmt.Errorf("unsupported endpoint %q (use unix:// or tcp://)", endpoint)
	}
	return c, nil
}

// get fetches path and decodes the JSON answer into v (v nil = ignore body).
func (c *dockerClient) get(path string, v any) error {
	resp, err := c.http.Get(c.base + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(body, &e) == nil && e.Message != "" {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, e.Message)
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if v == nil {
		return nil
	}
	return json.Unmarshal(body, v)
}

// dockerCheck is the result of one round for one daemon.
type dockerCheck struct {
	Daemon   probe
	Host     string // "hostname · OS" of the machine the daemon runs on
	Info     string
	Warnings []string
	// ContainerError is set when nothing is known about the containers (daemon
	// not reachable, list failed); the store then marks the known ones failed.
	ContainerError string
	// Containers: every container on the daemon sorted by name, plus a "not
	// found" row for each monitored name that matches none.
	Containers []containerResult
}

func checkDocker(t dockerTarget, timeout time.Duration) dockerCheck {
	now := time.Now().Format(time.RFC3339)
	res := dockerCheck{Daemon: probe{CheckedAt: now}}

	c, err := newDockerClient(t.Endpoint, timeout)
	if err != nil {
		res.Daemon.Error = err.Error()
		res.ContainerError = "daemon not reachable"
		return res
	}

	start := time.Now()
	err = c.get("/_ping", nil)
	res.Daemon.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Daemon.Error = shortNetError(err)
		res.ContainerError = "daemon not reachable"
		return res
	}
	res.Daemon.OK = true

	var version struct {
		Version    string
		APIVersion string `json:"ApiVersion"`
	}
	var info struct {
		Name              string // hostname of the Docker host
		OperatingSystem   string
		ContainersRunning int
		ContainersPaused  int
		ContainersStopped int
		Warnings          []string
	}
	if err := c.get("/version", &version); err == nil {
		res.Daemon.Detail = "Engine " + version.Version + " · API " + version.APIVersion
	}
	if err := c.get("/info", &info); err == nil {
		// Through the socket proxy the endpoint is only "tcp://docker-proxy:2375",
		// so the page shows the daemon's host instead.
		res.Host = strings.Join(nonEmpty(info.Name, info.OperatingSystem), " · ")
		res.Info = fmt.Sprintf("%d running · %d stopped", info.ContainersRunning, info.ContainersStopped)
		if info.ContainersPaused > 0 {
			res.Info += fmt.Sprintf(" · %d paused", info.ContainersPaused)
		}
		// Daemon warnings are often permanent and harmless (e.g. "No swap limit
		// support"), so they are only shown, they do not make the daemon WARN.
		res.Warnings = info.Warnings
	}

	var list []containerSummary
	if err := c.get("/containers/json?all=1", &list); err != nil {
		res.ContainerError = "container list: " + shortNetError(err)
		return res
	}
	// Every container on the daemon is shown; the monitored ones must run,
	// and one that is gone (docker compose down) gets a "not found" row.
	// How many containers each monitored name matches: a name that
	// matches several (a scaled compose service) cannot be the identity
	// of one of them, so those keep their container names.
	matches := map[string]int{}
	for _, s := range list {
		for _, m := range t.Monitored {
			if s.matches(m) {
				matches[m]++
			}
		}
	}
	for _, s := range list {
		cc := inspectContainer(c, s, s.name(), now)
		for _, m := range t.Monitored {
			if s.matches(m) {
				cc.Monitored = true
				if matches[m] == 1 {
					cc.MonitorName = m
				}
			}
		}
		res.Containers = append(res.Containers, cc)
	}
	for _, m := range t.Monitored {
		if matches[m] == 0 {
			res.Containers = append(res.Containers, containerResult{Name: m, Monitored: true, MonitorName: m,
				Probe: probe{CheckedAt: now, Error: "container not found"}})
		}
	}
	sort.Slice(res.Containers, func(i, j int) bool { return res.Containers[i].Name < res.Containers[j].Name })
	return res
}

// composeServiceLabel holds the compose service name of a container.
const composeServiceLabel = "com.docker.compose.service"

type containerSummary struct {
	ID     string `json:"Id"`
	Names  []string
	Labels map[string]string
}

func (s containerSummary) name() string {
	if len(s.Names) == 0 {
		return s.ID
	}
	return strings.TrimPrefix(s.Names[0], "/")
}

// hasName reports whether name is one of the container's names (the API
// gives them with a leading "/").
func (s containerSummary) hasName(name string) bool {
	for _, n := range s.Names {
		if strings.TrimPrefix(n, "/") == name {
			return true
		}
	}
	return false
}

// matches reports whether name is the container's name or its compose
// service name.
func (s containerSummary) matches(name string) bool {
	return s.hasName(name) || s.Labels[composeServiceLabel] == name
}

// inspectContainer reads the state of container s; name is how the page shows it.
func inspectContainer(c *dockerClient, s containerSummary, name, now string) containerResult {
	cc := containerResult{Name: name, Probe: probe{CheckedAt: now}}
	cc.Container = s.name()
	cc.Service = s.Labels[composeServiceLabel]
	cc.ID = s.ID

	var ins struct {
		RestartCount int
		Config       struct{ Image string }
		State        struct {
			Status     string
			Running    bool
			Restarting bool
			ExitCode   int
			StartedAt  time.Time
			FinishedAt time.Time
			Health     *struct{ Status string }
		}
	}
	if err := c.get("/containers/"+url.PathEscape(s.ID)+"/json", &ins); err != nil {
		cc.Probe.Error = shortNetError(err)
		return cc
	}
	cc.Image = ins.Config.Image
	cc.RestartCount = ins.RestartCount
	st := ins.State

	health := ""
	if st.Health != nil {
		health = st.Health.Status
	}
	status := st.Status
	if health != "" {
		status += " · " + health
	}

	if st.Running && !st.Restarting {
		cc.Uptime = "up " + shortDuration(time.Since(st.StartedAt))
	}
	switch {
	case st.Restarting:
		cc.Probe.Warn = true
		cc.Probe.Error = status
		cc.Uptime = "exit code " + fmt.Sprint(st.ExitCode)
	case st.Running && health == "unhealthy":
		cc.Probe.Warn = true
		cc.Probe.Error = status
	case st.Running && health == "starting":
		cc.Probe.Pending = true
		cc.Probe.Detail = status
	case st.Running:
		cc.Probe.OK = true
		cc.Probe.Detail = status
	default:
		// "exited" and "created" are shown as STOPPED; "dead" etc. stay FAIL.
		cc.Probe.Stopped = st.Status == "exited" || st.Status == "created"
		cc.Probe.Error = fmt.Sprintf("%s (exit code %d)", st.Status, st.ExitCode)
		if st.Status == "created" {
			cc.Probe.Error = "created (never started)"
		}
		if st.FinishedAt.Year() > 1 { // Docker sends 0001-01-01 when it never ran
			cc.Uptime = "down " + shortDuration(time.Since(st.FinishedAt))
		}
	}
	return cc
}

func nonEmpty(s ...string) []string {
	var out []string
	for _, v := range s {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// shortDuration formats d as e.g. "3d 4h", "2h 5m" or "45s".
func shortDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	case mins > 0:
		return fmt.Sprintf("%dm", mins)
	default:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
}

// shortNetError turns a timeout into "timeout", a DNS error into "DNS: ...",
// a system error into its text (e.g. "connection refused") and strips the
// URL that net/http puts in front of every other error.
func shortNetError(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	// "dial tcp 127.0.0.1:443: connect: connection refused" -> "connection refused"
	var de *net.DNSError
	if errors.As(err, &de) {
		return "DNS: " + shortDNSError(err)
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno.Error()
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}
