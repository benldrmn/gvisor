// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package egressallowlist

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestDomainMatcher(t *testing.T) {
	m, err := NewDomainMatcher([]string{"docs.github.com", "*.github.com", "Example.COM"})
	if err != nil {
		t.Fatalf("NewDomainMatcher: %v", err)
	}
	cases := []struct {
		name string
		want bool
	}{
		{"docs.github.com", true},
		{"DOCS.GITHUB.COM", true}, // caller normalizes, test normalized input
		{"a.github.com", true},
		{"a.b.github.com", true},
		{"github.com", false},      // wildcard excludes apex
		{"evilgithub.com", false},  // not a subdomain
		{"example.com", true},      // exact, case-folded at config time
		{"sub.example.com", false}, // exact does not imply subdomains
		{"notgithub.com", false},
	}
	for _, c := range cases {
		if got := m.Match(NormalizeName(c.name)); got != c.want {
			t.Errorf("Match(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDomainMatcherValidation(t *testing.T) {
	longLabel := strings.Repeat("a", 64) + ".example.com"
	longName := strings.Repeat("a.", 127) + "example.com"
	bad := []string{"*", "*.", "*foo.example.com", "foo.*.example.com", "a..b", "münchen.de", "has space.com", longLabel, longName}
	for _, p := range bad {
		if _, err := NewDomainMatcher([]string{p}); err == nil {
			t.Errorf("NewDomainMatcher(%q) accepted an invalid pattern", p)
		}
	}
	good := []string{"docs.github.com", "*.github.com", "_service.example.com", "a-b.example.com", "example.com.", "single", "*.internal", "*.com", "xn--literal"}
	for _, p := range good {
		if _, err := NewDomainMatcher([]string{p}); err != nil {
			t.Errorf("NewDomainMatcher(%q) rejected a valid pattern: %v", p, err)
		}
	}
}

func TestDomainListSubset(t *testing.T) {
	base := []string{"exact.example.com", "*.allowed.example"}
	for _, tc := range []struct {
		name   string
		list   []string
		within bool
	}{
		{"same exact", []string{"exact.example.com"}, true},
		{"exact below wildcard", []string{"a.allowed.example"}, true},
		{"narrower wildcard", []string{"*.a.allowed.example"}, true},
		{"wildcard apex", []string{"allowed.example"}, false},
		{"wildcard wider than exact", []string{"*.exact.example.com"}, false},
		{"outside", []string{"other.example.com"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uncovered, got, err := DomainListSubset(tc.list, base)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.within {
				t.Fatalf("DomainListSubset(%v, %v) = %t, uncovered %q, want %t", tc.list, base, got, uncovered, tc.within)
			}
		})
	}
}

func TestParseIPEntry(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"8.8.8.8", "8.8.8.8/32"},
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"10.1.2.3/8", "10.0.0.0/8"}, // masked to the network address
		{"2001:db8::1", "2001:db8::1/128"},
		{"2001:4860::/32", "2001:4860::/32"},
		{"::ffff:8.8.8.8", "8.8.8.8/32"},     // v4-in-v6 unmapped
		{"::ffff:8.8.8.0/120", "8.8.8.0/24"}, // prefix re-expressed over v4
		{" 8.8.4.4 ", "8.8.4.4/32"},          // surrounding whitespace
	}
	for _, c := range cases {
		got, err := ParseIPEntry(c.raw)
		if err != nil {
			t.Errorf("ParseIPEntry(%q): %v", c.raw, err)
			continue
		}
		if got != netip.MustParsePrefix(c.want) {
			t.Errorf("ParseIPEntry(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}

func TestParseIPEntryRejects(t *testing.T) {
	bad := []string{"not-an-ip", "8.8.8.8/40", "fe80::1%eth0", "999.1.1.1", "::ffff:1.2.3.4/40", "10.0.0.0/-1", ""}
	for _, raw := range bad {
		if _, err := ParseIPEntry(raw); err == nil {
			t.Errorf("ParseIPEntry(%q) accepted an invalid entry", raw)
		}
	}
}

func TestParseIPList(t *testing.T) {
	got, err := ParseIPList([]string{
		"8.8.8.8",
		"10.0.0.0/8",
		"", " ", // blanks are skipped
		"10.1.2.3/8",     // masks to 10.0.0.0/8, duplicate
		"::ffff:8.8.8.8", // unmaps to 8.8.8.8, duplicate
		"2001:db8::1",
	})
	if err != nil {
		t.Fatalf("ParseIPList: %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("8.8.8.8/32"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::1/128"),
	}
	if len(got) != len(want) {
		t.Fatalf("ParseIPList returned %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ParseIPList[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestParseIPListCap(t *testing.T) {
	distinct := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("10.1.%d.%d", i>>8, i&0xff)
		}
		return out
	}
	if _, err := ParseIPList(distinct(MaxListEntries)); err != nil {
		t.Errorf("ParseIPList with %d distinct entries: %v", MaxListEntries, err)
	}
	if _, err := ParseIPList(distinct(MaxListEntries + 1)); err == nil {
		t.Errorf("ParseIPList accepted %d distinct entries, cap is %d", MaxListEntries+1, MaxListEntries)
	}
	// Duplicates collapse before the cap is applied, so a repetitive list that
	// allows little is not rejected.
	dups := make([]string, MaxListEntries+100)
	for i := range dups {
		dups[i] = "10.0.0.0/8"
	}
	if _, err := ParseIPList(dups); err != nil {
		t.Errorf("ParseIPList with %d duplicates of one entry: %v", len(dups), err)
	}
}

func TestIPListSubset(t *testing.T) {
	base := []string{"10.0.0.0/8", "2001:db8::1"}
	for _, tc := range []struct {
		name   string
		list   []string
		within bool
	}{
		{"address in prefix", []string{"10.1.2.3"}, true},
		{"narrower prefix", []string{"10.2.0.0/16"}, true},
		{"same v6 address", []string{"2001:db8::1"}, true},
		{"wider prefix", []string{"10.0.0.0/7"}, false},
		{"outside", []string{"11.0.0.1"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uncovered, got, err := IPListSubset(tc.list, base)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.within {
				t.Fatalf("IPListSubset(%v, %v) = %t, uncovered %q, want %t", tc.list, base, got, uncovered, tc.within)
			}
		})
	}
}

func TestDomainMatcherCap(t *testing.T) {
	distinct := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("h%d.example.com", i)
		}
		return out
	}
	if _, err := NewDomainMatcher(distinct(MaxListEntries)); err != nil {
		t.Errorf("NewDomainMatcher with %d distinct patterns: %v", MaxListEntries, err)
	}
	if _, err := NewDomainMatcher(distinct(MaxListEntries + 1)); err == nil {
		t.Errorf("NewDomainMatcher accepted %d distinct patterns, cap is %d", MaxListEntries+1, MaxListEntries)
	}
	// Duplicates collapse in the matcher's maps and do not count toward the cap.
	dups := make([]string, MaxListEntries+100)
	for i := range dups {
		dups[i] = "dup.example.com"
	}
	if _, err := NewDomainMatcher(dups); err != nil {
		t.Errorf("NewDomainMatcher with %d duplicates of one pattern: %v", len(dups), err)
	}
}
