package main

import "testing"

func TestShortModuleVersion(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", ""},
		{"(devel)", ""},
		{"v0.3.6", "v0.3.6"},
		{"v0.3.6+dirty", "v0.3.6-dirty"},
		{"v0.0.0-20260929070254-5ba2487a7445", "5ba2487"},
		{"v0.0.0-20260929070254-5ba2487a7445+dirty", "5ba2487-dirty"},
		{"v0.3.7-0.20260929070254-5ba2487a7445", "v0.3.6-5ba2487"},
		{"v0.3.7-0.20260929070254-5ba2487a7445+dirty", "v0.3.6-5ba2487-dirty"},
		{"v1.0.0-rc1", "v1.0.0-rc1"},
		{"v0.4.0-rc1.0.20260929070254-5ba2487a7445", "v0.4.0-rc1-5ba2487"},
	} {
		if got := shortModuleVersion(c.in); got != c.want {
			t.Errorf("shortModuleVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
