package main

import (
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
)

// version can be set at build time, for builds without the git folder
// (e.g. a Docker build that does not copy .git):
//
//	go build -ldflags "-X main.version=v0.4.0"
//
// A plain "go build" in the git working copy leaves it empty; appVersion then
// uses the version Go records from the git tag (Go 1.24 and later), so the
// same commit shows the same version on Windows and Linux.
var version string

// appVersion returns the version shown on the HELP page, in the log and by
// -version: "v0.3.6" on a tagged commit, "v0.3.6-5ba2487" on a later commit
// (the last tag and the commit), "5ba2487" without any tag; "-dirty" when
// there were uncommitted changes. Else "dev".
// Worked out once, the status API asks for it on every refresh.
var appVersion = sync.OnceValue(func() string {
	if version != "" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := shortModuleVersion(info.Main.Version); v != "" {
		return v
	}
	// No module version (e.g. "go run", or Go older than 1.24): the commit.
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "dev"
	}
	if len(rev) > 7 {
		rev = rev[:7]
	}
	if dirty {
		rev += "-dirty"
	}
	return rev
})

// Pseudo-versions Go gives an untagged commit (the timestamp is 14 digits,
// the commit 12 hex digits):
//
//	v0.0.0-20260929070254-5ba2487a7445       no tag yet
//	v0.3.7-0.20260929070254-5ba2487a7445     after tag v0.3.6
//	v0.4.0-rc1.0.20260929070254-5ba2487a7445 after tag v0.4.0-rc1
var (
	pseudoNoTag   = regexp.MustCompile(`^v0\.0\.0-\d{14}-([0-9a-f]{7})[0-9a-f]{5}$`)
	pseudoRelease = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)-0\.\d{14}-([0-9a-f]{7})[0-9a-f]{5}$`)
	pseudoPre     = regexp.MustCompile(`^(v\d+\.\d+\.\d+-.+)\.0\.\d{14}-([0-9a-f]{7})[0-9a-f]{5}$`)
)

// shortModuleVersion turns the module version Go records into the form
// described at appVersion; "" when there is none ("(devel)").
func shortModuleVersion(v string) string {
	if v == "" || v == "(devel)" {
		return ""
	}
	v, dirty := strings.CutSuffix(v, "+dirty")
	if m := pseudoNoTag.FindStringSubmatch(v); m != nil {
		v = m[1]
	} else if m := pseudoRelease.FindStringSubmatch(v); m != nil {
		// The pseudo-version counts up the patch of the last tag.
		patch, _ := strconv.Atoi(m[3])
		v = "v" + m[1] + "." + m[2] + "." + strconv.Itoa(patch-1) + "-" + m[4]
	} else if m := pseudoPre.FindStringSubmatch(v); m != nil {
		v = m[1] + "-" + m[2]
	}
	if dirty {
		v += "-dirty"
	}
	return v
}
