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
)

// ParseIPEntry parses a single allowlist entry, an IP address or a CIDR, into
// a normalized netip.Prefix. A bare address becomes a full-length prefix.
// Addresses are canonicalized (v4-in-v6 unmapped, prefix length re-expressed
// over the 32-bit form) so an IPv4 destination compares equal to a
// "::ffff:a.b.c.d" entry. Zoned addresses are rejected.
func ParseIPEntry(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("egress CIDR %q is not valid: %v", raw, err)
		}
		bits := p.Bits()
		if p.Addr().Is4In6() {
			bits -= 96
			if bits < 0 {
				return netip.Prefix{}, fmt.Errorf("egress CIDR %q has an invalid v4-in-v6 prefix length", raw)
			}
		}
		return netip.PrefixFrom(p.Addr().Unmap(), bits).Masked(), nil
	}
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("egress IP %q is not a valid address: %v", raw, err)
	}
	if a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("egress IP %q must not have a zone", raw)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ParseIPList parses a list of IP/CIDR entries into normalized, deduplicated
// prefixes, preserving first-seen order. Blank entries are skipped. It fails if
// any entry is invalid or if more than MaxListEntries distinct prefixes remain
// after deduplication. Deduplication runs first so a list with repeated entries
// is judged by what it actually allows.
func ParseIPList(entries []string) ([]netip.Prefix, error) {
	seen := make(map[netip.Prefix]struct{}, len(entries))
	var out []netip.Prefix
	for _, raw := range entries {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		p, err := ParseIPEntry(raw)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if len(out) > MaxListEntries {
		return nil, fmt.Errorf("egress IP allowlist has %d distinct entries, the limit is %d", len(out), MaxListEntries)
	}
	return out, nil
}
