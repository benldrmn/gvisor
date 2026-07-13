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

// Package egressallowlist provides parsing and matching for egress allowlist
// entries (domain patterns and IP/CIDR entries). It is the single source of
// truth shared by runsc flag validation and the Sentry's egress filter, so a
// value that passes flag validation cannot later fail in the Sentry.
package egressallowlist

import (
	"fmt"
	"strings"
)

const (
	// maxDomainNameLen is the maximum length of a domain name in presentation
	// form that we accept in a pattern, per RFC 1035 (255 octets on the wire,
	// which is at most 253 presentation characters).
	maxDomainNameLen = 253
	// maxLabelLen is the maximum length of a single DNS label, per RFC 1035.
	maxLabelLen = 63

	// MaxListEntries bounds each egress allowlist (IP/CIDR and domain), counted
	// after normalization and deduplication. The CIDR list is scanned linearly on
	// the packet hot path and OCI annotations can supply it, so it must not grow
	// without bound. The limit is far above any hand-written policy.
	MaxListEntries = 1024
)

// DomainMatcher decides whether a DNS name is on the allowlist. Both exact
// names ("docs.github.com") and wildcards ("*.github.com") are supported. A
// wildcard matches subdomains at any depth (a.b.github.com) but never the apex
// (github.com). List the apex separately to allow it.
//
// The zero value matches nothing. It is immutable after construction and safe
// for concurrent reads without locking.
type DomainMatcher struct {
	// exact holds normalized exact names, e.g. "docs.github.com".
	exact map[string]struct{}
	// wildcard holds the normalized suffix of a "*." pattern, e.g. the pattern
	// "*.github.com" is stored as "github.com". A name n matches iff n ends
	// with "." + suffix (guaranteeing a label boundary and depth >= 1).
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

// SplitList splits a comma-separated flag or annotation value into non-empty,
// trimmed entries. It is the shared splitting rule for flag validation,
// annotation override checks, and the Sentry's filter construction.
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

// Match reports whether name (which must already be normalized via
// NormalizeName) is allowed.
func (m *DomainMatcher) Match(name string) bool {
	if _, ok := m.exact[name]; ok {
		return true
	}
	if len(m.wildcard) == 0 {
		return false
	}
	// Walk each label boundary: for "a.b.github.com", test suffixes
	// "b.github.com", "github.com", "com". A wildcard "*.github.com" (stored as
	// "github.com") matches because we only test proper suffixes that begin
	// after a dot, so the apex "github.com" itself is never tested against its
	// own wildcard.
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

// NormalizeName canonicalizes a DNS name for matching: ASCII-lowercased with a
// single trailing dot stripped. DNS is case-insensitive and resolvers randomize
// case ("DNS 0x20"), so matching must fold case.
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

// validateDomainName checks that name (already normalized, wildcard stripped) is
// a syntactically valid domain name. orig is the caller-supplied pattern, used
// only for error messages.
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
