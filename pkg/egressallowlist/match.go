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

// Package egressallowlist parses and matches domain and IP allowlists for runsc
// configuration and the Sentry's egress filter.
package egressallowlist

import (
	"fmt"
	"strings"
)

const (
	// maxDomainNameLen excludes the trailing dot. RFC 1035 limits wire names to
	// 255 octets, leaving 253 presentation characters.
	maxDomainNameLen = 253
	// maxLabelLen is the maximum length of a single DNS label, per RFC 1035.
	maxLabelLen = 63

	// MaxListEntries limits distinct entries in each normalized allowlist.
	// This bounds the per-packet scan of CIDR entries.
	MaxListEntries = 1024
)

// DomainMatcher matches exact names and "*." patterns. Wildcards match
// subdomains at any depth, but not the suffix itself.
//
// The zero value matches nothing. After construction, a DomainMatcher is
// immutable and safe for concurrent use.
type DomainMatcher struct {
	// exact holds normalized exact names, e.g. "docs.github.com".
	exact map[string]struct{}
	// wildcard holds pattern suffixes without the "*." prefix.
	wildcard map[string]struct{}
}

// NewDomainMatcher parses and validates the given patterns.
func NewDomainMatcher(patterns []string) (DomainMatcher, error) {
	m := DomainMatcher{
		exact:    make(map[string]struct{}),
		wildcard: make(map[string]struct{}),
	}
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		suffix, wildcard, err := ParseDomainPattern(p)
		if err != nil {
			return DomainMatcher{}, err
		}
		if wildcard {
			m.wildcard[suffix] = struct{}{}
		} else {
			m.exact[suffix] = struct{}{}
		}
	}
	if n := len(m.exact) + len(m.wildcard); n > MaxListEntries {
		return DomainMatcher{}, fmt.Errorf("egress domain allowlist has %d distinct patterns, the limit is %d", n, MaxListEntries)
	}
	return m, nil
}

// SplitList splits a comma-separated value into non-empty, trimmed entries.
func SplitList(csv string) []string {
	var out []string
	for _, raw := range strings.Split(csv, ",") {
		if raw = strings.TrimSpace(raw); raw != "" {
			out = append(out, raw)
		}
	}
	return out
}

// Empty reports whether the matcher contains no patterns.
func (m *DomainMatcher) Empty() bool {
	return len(m.exact) == 0 && len(m.wildcard) == 0
}

// Match reports whether name is allowed.
//
// Preconditions: name has been normalized with NormalizeName.
func (m *DomainMatcher) Match(name string) bool {
	if _, ok := m.exact[name]; ok {
		return true
	}
	if len(m.wildcard) == 0 {
		return false
	}
	// Check only suffixes after a dot so wildcards exclude the apex.
	rest := name
	for {
		i := strings.IndexByte(rest, '.')
		if i < 0 {
			return false
		}
		rest = rest[i+1:]
		if _, ok := m.wildcard[rest]; ok {
			return true
		}
	}
}

// NormalizeName lowercases ASCII letters and removes one trailing dot.
func NormalizeName(name string) string {
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return asciiLower(name)
}

// asciiLower lowercases ASCII letters without allocating when the input is
// already lowercase.
func asciiLower(s string) string {
	hasUpper := false
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return s
	}
	b := []byte(s)
	for i := range b {
		if c := b[i]; c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// ParseDomainPattern validates a single allowlist pattern and returns its
// normalized suffix and whether it is a wildcard. It rejects bare "*",
// misplaced wildcards, non-ASCII, and malformed labels. ASCII names beginning
// with "xn--" are treated literally. This parser does not perform IDNA checks.
func ParseDomainPattern(pattern string) (suffix string, wildcard bool, err error) {
	p := NormalizeName(strings.TrimSpace(pattern))
	if p == "" {
		return "", false, fmt.Errorf("egress domain pattern is empty")
	}
	if p == "*" {
		return "", false, fmt.Errorf("egress domain pattern %q is too broad: a bare wildcard is not allowed", pattern)
	}
	if strings.HasPrefix(p, "*.") {
		wildcard = true
		p = p[len("*."):]
		if p == "" {
			return "", false, fmt.Errorf("egress domain pattern %q has no domain after the wildcard", pattern)
		}
	}
	if err := validateDomainName(p, pattern); err != nil {
		return "", false, err
	}
	return p, wildcard, nil
}

// validateDomainName checks a normalized name with the wildcard removed.
// orig is the original pattern, used in errors.
func validateDomainName(name, orig string) error {
	if len(name) > maxDomainNameLen {
		return fmt.Errorf("egress domain %q is longer than %d characters", orig, maxDomainNameLen)
	}
	if strings.Contains(name, "*") {
		return fmt.Errorf("egress domain %q may only use a wildcard as the entire first label (e.g. *.example.com)", orig)
	}
	for _, label := range strings.Split(name, ".") {
		if err := validateLabel(label, orig); err != nil {
			return err
		}
	}
	return nil
}

// validateLabel checks a single DNS label. Underscores are accepted as literal
// on-wire DNS characters. Non-ASCII configuration strings are rejected.
func validateLabel(label, orig string) error {
	if label == "" {
		return fmt.Errorf("egress domain %q has an empty label", orig)
	}
	if len(label) > maxLabelLen {
		return fmt.Errorf("egress domain %q has a label longer than %d characters", orig, maxLabelLen)
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_':
		case c >= 0x80:
			return fmt.Errorf("egress domain %q must be ASCII", orig)
		default:
			return fmt.Errorf("egress domain %q contains an invalid character %q", orig, string(rune(c)))
		}
	}
	return nil
}

// DomainListSubset reports whether every pattern in subset is covered by a
// pattern in superset. uncovered is the first pattern that is not covered.
func DomainListSubset(subset, superset []string) (uncovered string, ok bool, err error) {
	type pattern struct {
		suffix   string
		wildcard bool
	}
	base := make([]pattern, 0, len(superset))
	for _, raw := range superset {
		suffix, wildcard, err := ParseDomainPattern(raw)
		if err != nil {
			return "", false, err
		}
		base = append(base, pattern{suffix: suffix, wildcard: wildcard})
	}
	for _, raw := range subset {
		suffix, wildcard, err := ParseDomainPattern(raw)
		if err != nil {
			return "", false, err
		}
		covered := false
		for _, candidate := range base {
			if domainPatternCovered(suffix, wildcard, candidate.suffix, candidate.wildcard) {
				covered = true
				break
			}
		}
		if !covered {
			return raw, false, nil
		}
	}
	return "", true, nil
}

func domainPatternCovered(suffix string, wildcard bool, baseSuffix string, baseWildcard bool) bool {
	if !baseWildcard {
		return !wildcard && suffix == baseSuffix
	}
	if !wildcard {
		return strings.HasSuffix(suffix, "."+baseSuffix)
	}
	return suffix == baseSuffix || strings.HasSuffix(suffix, "."+baseSuffix)
}
