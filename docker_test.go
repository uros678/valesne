package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeContainers is the state of the fake daemon: container ID -> status
// ("running", "exited"); a test can remove a container (compose down).
type fakeContainers struct {
	mu sync.Mutex
	m  map[string]string
}

func (f *fakeContainers) set(id, status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if status == "" {
		delete(f.m, id)
	} else {
		f.m[id] = status
	}
}

// fakeDocker serves the few read-only Docker Engine API calls valesne
// makes: two containers, "web" running and "db" exited, both from a
// compose project.
func fakeDocker(t *testing.T) string {
	endpoint, _ := fakeDockerState(t)
	return endpoint
}

func fakeDockerState(t *testing.T) (string, *fakeContainers) {
	state := &fakeContainers{m: map[string]string{"id-web": "running", "id-db": "exited"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		containers := state.m
		switch {
		case r.URL.Path == "/_ping":
			w.Write([]byte("OK"))
		case r.URL.Path == "/version":
			json.NewEncoder(w).Encode(map[string]string{"Version": "29.0", "ApiVersion": "1.52"})
		case r.URL.Path == "/info":
			json.NewEncoder(w).Encode(map[string]any{"Name": "server", "ContainersRunning": 1, "ContainersStopped": 1})
		case r.URL.Path == "/containers/json":
			var list []map[string]any
			for id := range containers {
				svc := strings.TrimPrefix(id, "id-")
				list = append(list, map[string]any{"Id": id, "Names": []string{"/home-" + svc + "-1"},
					"Labels": map[string]string{"com.docker.compose.service": svc}})
			}
			json.NewEncoder(w).Encode(list)
		case strings.HasPrefix(r.URL.Path, "/containers/"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/containers/"), "/json")
			status := containers[id]
			json.NewEncoder(w).Encode(map[string]any{"State": map[string]any{
				"Status": status, "Running": status == "running",
				"StartedAt": time.Now().Add(-time.Hour), "FinishedAt": time.Now().Add(-time.Minute),
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return "tcp://" + strings.TrimPrefix(srv.URL, "http://"), state
}

func TestDockerMonitored(t *testing.T) {
	endpoint := fakeDocker(t)
	res := checkDocker(dockerTarget{Name: "Docker", Endpoint: endpoint,
		Monitored: []string{"web", "db", "gone"}}, 3*time.Second)
	byName := map[string]containerResult{}
	for _, c := range res.Containers {
		byName[c.Name] = c
	}
	if len(res.Containers) != 3 {
		t.Fatalf("got %d containers, want 2 found + 1 not found", len(res.Containers))
	}
	if c := byName["home-web-1"]; !c.Monitored || !c.Probe.OK {
		t.Errorf("web: monitored %v ok %v", c.Monitored, c.Probe.OK)
	}
	if c := byName["home-db-1"]; !c.Monitored || !c.Probe.Stopped {
		t.Errorf("db: monitored %v stopped %v", c.Monitored, c.Probe.Stopped)
	}
	if c := byName["gone"]; !c.Monitored || c.Probe.Error != "container not found" {
		t.Errorf("gone: monitored %v %q", c.Monitored, c.Probe.Error)
	}

	// Without monitored: the stopped one is only shown, nothing is missing.
	res = checkDocker(dockerTarget{Name: "Docker", Endpoint: endpoint}, 3*time.Second)
	for _, c := range res.Containers {
		if c.Monitored {
			t.Errorf("%s is monitored without a monitored list", c.Name)
		}
	}
	if len(res.Containers) != 2 {
		t.Errorf("got %d containers, want 2", len(res.Containers))
	}
}

// TestDockerMonitoredAlerts runs the results through the store and alerting:
// a stopped monitored container is DOWN and alerts, an unmonitored one is
// only counted as stopped.
func TestDockerMonitoredAlerts(t *testing.T) {
	endpoint := fakeDocker(t)
	for _, c := range []struct {
		monitored []string
		wantDown  int
		wantStop  int
	}{
		{nil, 0, 1},
		{[]string{"db"}, 1, 0},
	} {
		cfg := config{Docker: []dockerTarget{{Name: "Docker", Endpoint: endpoint, Monitored: c.monitored}}}
		st := newStore(cfg)
		st.setDocker(st.gen, 0, checkDocker(cfg.Docker[0], 3*time.Second))
		snap := st.snapshot()
		if snap.Down != c.wantDown || snap.Stopped != c.wantStop {
			t.Errorf("monitored %v: down %d stopped %d, want %d / %d", c.monitored, snap.Down, snap.Stopped, c.wantDown, c.wantStop)
		}
		fails := 0
		for _, it := range alertItems(snap, false) {
			if it.level == levelFail {
				fails++
			}
		}
		if fails != c.wantDown {
			t.Errorf("monitored %v: %d alerting items, want %d", c.monitored, fails, c.wantDown)
		}
	}
}

// TestDockerComposeDownUp: a monitored container keeps its identity for
// alerting ("web") whether it runs as "home-web-1" or is gone, so
// compose down alerts DOWN and compose up alerts recovered.
func TestDockerComposeDownUp(t *testing.T) {
	endpoint, state := fakeDockerState(t)
	cfg := config{Docker: []dockerTarget{{Name: "Docker", Endpoint: endpoint, Monitored: []string{"web"}}}}
	st := newStore(cfg)
	a, clock := testAlerter()
	round := func() []alertChange {
		clock.t = clock.t.Add(time.Minute)
		st.setDocker(st.gen, 0, checkDocker(cfg.Docker[0], 3*time.Second))
		return a.evaluate(alertItems(st.snapshot(), false), 1)
	}

	if got := round(); len(got) != 0 {
		t.Fatalf("running: %d changes", len(got))
	}
	state.set("id-web", "") // compose down
	got := round()
	if len(got) != 1 || got[0].item.level != levelFail || got[0].item.name != "web" {
		t.Fatalf("compose down: %+v", got)
	}
	state.set("id-web", "running") // compose up
	got = round()
	if len(got) != 1 || got[0].item.level != levelOK || got[0].item.name != "web" {
		t.Fatalf("compose up: want web recovered, got %+v", got)
	}
}

// TestDockerDaemonGone: when the daemon cannot be reached, the known
// containers keep their identity (name, monitored, compose service) with the
// error and no uptime.
func TestDockerDaemonGone(t *testing.T) {
	endpoint := fakeDocker(t)
	cfg := config{Docker: []dockerTarget{{Name: "Docker", Endpoint: endpoint, Monitored: []string{"web"}}}}
	st := newStore(cfg)
	st.setDocker(st.gen, 0, checkDocker(cfg.Docker[0], 3*time.Second))
	st.setDocker(st.gen, 0, dockerCheck{Daemon: probe{Error: "connection refused"}, ContainerError: "daemon not reachable"})
	cs := st.snapshot().Docker[0].Containers
	if len(cs) != 2 {
		t.Fatalf("got %d containers, want the 2 known ones", len(cs))
	}
	byName := map[string]containerResult{}
	for _, c := range cs {
		if c.Probe.Error != "daemon not reachable" || c.Probe.OK || c.Uptime != "" || c.Service == "" {
			t.Errorf("%s: %+v", c.Name, c)
		}
		byName[c.Name] = c
	}
	if c := byName["home-web-1"]; !c.Monitored || c.MonitorName != "web" {
		t.Errorf("web lost its identity: %+v", c)
	}
}
