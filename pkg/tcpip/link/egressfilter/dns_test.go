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

package egressfilter

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
)

// mustName builds a dnsmessage.Name, failing the test on error.
func mustName(t *testing.T, s string) dnsmessage.Name {
	t.Helper()
	n, err := dnsmessage.NewName(s)
	if err != nil {
		t.Fatalf("dnsmessage.NewName(%q): %v", s, err)
	}
	return n
}

// buildQuery builds a DNS query wire message.
func buildQuery(t *testing.T, id uint16, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, Response: false},
		Questions: []dnsmessage.Question{{
			Name:  mustName(t, name),
			Type:  qtype,
			Class: dnsmessage.ClassINET,
		}},
	}
	b, err := msg.Pack()
	if err != nil {
		t.Fatalf("packing query: %v", err)
	}
	return b
}

// aResource builds an A answer record.
func aResource(t *testing.T, owner string, ip [4]byte) dnsmessage.Resource {
	t.Helper()
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: mustName(t, owner), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.AResource{A: ip},
	}
}

// aaaaResource builds an AAAA answer record.
func aaaaResource(t *testing.T, owner string, ip [16]byte) dnsmessage.Resource {
	t.Helper()
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: mustName(t, owner), Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.AAAAResource{AAAA: ip},
	}
}

// cnameResource builds a CNAME answer record.
func cnameResource(t *testing.T, owner, target string) dnsmessage.Resource {
	t.Helper()
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: mustName(t, owner), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.CNAMEResource{CNAME: mustName(t, target)},
	}
}

// buildResponse builds a DNS response with the given question and answers.
func buildResponse(t *testing.T, id uint16, qname string, answers []dnsmessage.Resource) []byte {
	return buildResponseQuestion(t, id, qname, dnsmessage.TypeA, dnsmessage.ClassINET, answers)
}

func buildResponseQuestion(t *testing.T, id uint16, qname string, qtype dnsmessage.Type, qclass dnsmessage.Class, answers []dnsmessage.Resource) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, Response: true, RCode: dnsmessage.RCodeSuccess},
		Questions: []dnsmessage.Question{{
			Name:  mustName(t, qname),
			Type:  qtype,
			Class: qclass,
		}},
		Answers: answers,
	}
	b, err := msg.Pack()
	if err != nil {
		t.Fatalf("packing response: %v", err)
	}
	return b
}

func newTestFilter(t *testing.T, cfg Config) *Filter {
	t.Helper()
	if cfg.Clock == nil {
		cfg.Clock = faketime.NewManualClock()
	}
	f, err := NewFilter(cfg)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	return f
}

func TestParseDNSQuery(t *testing.T) {
	// The mixed-case name (DNS 0x20) must come back normalized.
	b := buildQuery(t, 0x1234, "Docs.GitHub.COM.", dnsmessage.TypeA)
	name, qType, txID, ok := parseDNSQuery(b)
	if !ok {
		t.Fatal("parseDNSQuery failed on a valid query")
	}
	if name != "docs.github.com" {
		t.Errorf("qname = %q, want docs.github.com", name)
	}
	if txID != 0x1234 {
		t.Errorf("txID = %#x, want 0x1234", txID)
	}
	if qType != dnsmessage.TypeA {
		t.Errorf("qType = %v, want A", qType)
	}
}

func TestParseDNSQueryRejects(t *testing.T) {
	// A response, not a query.
	resp := buildResponse(t, 1, "a.example.com.", nil)
	if _, _, _, ok := parseDNSQuery(resp); ok {
		t.Error("parseDNSQuery accepted a response")
	}
	// Two questions.
	twoQ := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 1},
		Questions: []dnsmessage.Question{
			{Name: mustName(t, "a.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			{Name: mustName(t, "b.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		},
	}
	b, _ := twoQ.Pack()
	if _, _, _, ok := parseDNSQuery(b); ok {
		t.Error("parseDNSQuery accepted a two-question query")
	}
	// Non-A/AAAA type.
	mx := buildQuery(t, 1, "a.example.com.", dnsmessage.TypeMX)
	if _, _, _, ok := parseDNSQuery(mx); ok {
		t.Error("parseDNSQuery accepted an MX query")
	}
	// Garbage.
	if _, _, _, ok := parseDNSQuery([]byte{0, 1, 2}); ok {
		t.Error("parseDNSQuery accepted garbage")
	}
}

// TestParseDNSQueryRejectsLiteralDotLabel pins x/net/dnsmessage's rejection of
// a wire-format label containing a literal dot. The string matcher treats dots
// as label boundaries, so accepting this name would let "a.b.github.com" match
// a packet whose first label is actually "a.b".
func TestParseDNSQueryRejectsLiteralDotLabel(t *testing.T) {
	// Header: ID 1, one question. QNAME labels: "a.b", "github", "com".
	b := []byte{
		0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		3, 'a', '.', 'b', 6, 'g', 'i', 't', 'h', 'u', 'b', 3, 'c', 'o', 'm', 0,
		0, 1, 0, 1,
	}
	if _, _, _, ok := parseDNSQuery(b); ok {
		t.Fatal("parseDNSQuery accepted a QNAME label containing a literal dot")
	}
}

func TestHarvestChain(t *testing.T) {
	f := newTestFilter(t, Config{})
	ip1 := [4]byte{151, 101, 1, 1}
	ip2 := [4]byte{151, 101, 2, 2}

	// docs.github.com CNAME github.map.fastly.net, which has two A records.
	answers := []dnsmessage.Resource{
		cnameResource(t, "docs.github.com.", "github.map.fastly.net."),
		aResource(t, "github.map.fastly.net.", ip1),
		aResource(t, "github.map.fastly.net.", ip2),
		// An unrelated A record a hostile resolver stuffed in: must be ignored.
		aResource(t, "evil.example.com.", [4]byte{6, 6, 6, 6}),
	}
	resp := buildResponse(t, 1, "docs.github.com.", answers)

	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Question(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Question(); err != dnsmessage.ErrSectionDone {
		t.Fatal("expected one question")
	}
	got := f.harvest(&p, "docs.github.com")
	want := map[tcpip.Address]bool{
		tcpip.AddrFrom4(ip1): true,
		tcpip.AddrFrom4(ip2): true,
	}
	if len(got) != len(want) {
		t.Fatalf("harvest returned %d addrs (%v), want %d", len(got), got, len(want))
	}
	for _, a := range got {
		if !want[a] {
			t.Errorf("harvest returned unexpected/forbidden addr %s", a)
		}
	}
}

func TestHarvestAAAA(t *testing.T) {
	f := newTestFilter(t, Config{})
	ip := [16]byte{0x26, 0x06, 0x28, 0x00}
	resp := buildResponse(t, 1, "docs.github.com.", []dnsmessage.Resource{
		cnameResource(t, "docs.github.com.", "github.map.fastly.net."),
		aaaaResource(t, "github.map.fastly.net.", ip),
	})
	var p dnsmessage.Parser
	p.Start(resp)
	p.Question()
	p.Question()
	got := f.harvest(&p, "docs.github.com")
	if len(got) != 1 || got[0] != tcpip.AddrFrom16(ip) {
		t.Fatalf("harvest = %v, want [%s]", got, tcpip.AddrFrom16(ip))
	}
}

func TestHarvestV4MappedAAAAUnmaps(t *testing.T) {
	f := newTestFilter(t, Config{})
	mapped := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4}
	resp := buildResponseQuestion(t, 1, "docs.github.com.", dnsmessage.TypeAAAA, dnsmessage.ClassINET, []dnsmessage.Resource{
		aaaaResource(t, "docs.github.com.", mapped),
	})
	var p dnsmessage.Parser
	p.Start(resp)
	p.Question()
	p.Question()
	got := f.harvest(&p, "docs.github.com")
	want := tcpip.AddrFrom4([4]byte{1, 2, 3, 4})
	if len(got) != 1 || got[0] != want {
		t.Fatalf("harvest = %v, want v4 address [%s]", got, want)
	}
	f.learned.addBatch(got)
	if !f.allowedDst(want) {
		t.Fatal("v4-mapped AAAA did not authorize the corresponding IPv4 destination")
	}
}

func TestHarvestRejectsNonINETRecords(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answers []dnsmessage.Resource
	}{
		{
			name: "A",
			answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: mustName(t, "a.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassCHAOS},
				Body:   &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}},
			}},
		},
		{
			name: "AAAA",
			answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: mustName(t, "a.example.com."), Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassCHAOS},
				Body:   &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 1, 0xdb, 8}},
			}},
		},
		{
			name: "CNAME",
			answers: []dnsmessage.Resource{
				{
					Header: dnsmessage.ResourceHeader{Name: mustName(t, "a.example.com."), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassCHAOS},
					Body:   &dnsmessage.CNAMEResource{CNAME: mustName(t, "target.example.com.")},
				},
				aResource(t, "target.example.com.", [4]byte{1, 2, 3, 4}),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTestFilter(t, Config{})
			resp := buildResponse(t, 1, "a.example.com.", tc.answers)
			var p dnsmessage.Parser
			p.Start(resp)
			p.Question()
			p.Question()
			if got := f.harvest(&p, "a.example.com"); len(got) != 0 {
				t.Fatalf("harvest learned from non-IN %s record: %v", tc.name, got)
			}
		})
	}
}

func TestLearnResponsePinsQuestionAndLocalAddress(t *testing.T) {
	server := tcpip.AddrFrom4([4]byte{8, 8, 8, 8})
	local := tcpip.AddrFrom4([4]byte{192, 168, 1, 2})
	otherLocal := tcpip.AddrFrom4([4]byte{192, 168, 1, 3})
	learned := tcpip.AddrFrom4([4]byte{1, 2, 3, 4})
	for _, tc := range []struct {
		name      string
		qType     dnsmessage.Type
		qClass    dnsmessage.Class
		respLocal tcpip.Address
	}{
		{"question type", dnsmessage.TypeAAAA, dnsmessage.ClassINET, local},
		{"question class", dnsmessage.TypeA, dnsmessage.ClassCHAOS, local},
		{"local address", dnsmessage.TypeA, dnsmessage.ClassINET, otherLocal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTestFilter(t, Config{})
			now := f.clock.NowMonotonic()
			key := pendingKey{server: server, local: local, clientPort: 40000, txID: 7}
			f.pending.track(key, "a.example.com", dnsmessage.TypeA, now, now.Add(queryTTL))
			resp := buildResponseQuestion(t, 7, "a.example.com.", tc.qType, tc.qClass, []dnsmessage.Resource{
				aResource(t, "a.example.com.", [4]byte{1, 2, 3, 4}),
			})
			f.learnFromResponse(resp, server, tc.respLocal, 40000)
			if f.learned.contains(learned) {
				t.Fatalf("learned from response with mismatched %s", tc.name)
			}
			// A mismatch must not consume the pending query.
			valid := buildResponse(t, 7, "a.example.com.", []dnsmessage.Resource{
				aResource(t, "a.example.com.", [4]byte{1, 2, 3, 4}),
			})
			f.learnFromResponse(valid, server, local, 40000)
			if !f.learned.contains(learned) {
				t.Fatal("mismatched response consumed the pending query")
			}
		})
	}
}

func TestHarvestApexFlattened(t *testing.T) {
	f := newTestFilter(t, Config{})
	ip := [4]byte{140, 82, 121, 3}
	// Apex A record directly at the queried name (ALIAS/flattening), no CNAME.
	resp := buildResponse(t, 1, "github.com.", []dnsmessage.Resource{
		aResource(t, "github.com.", ip),
	})
	var p dnsmessage.Parser
	p.Start(resp)
	p.Question()
	p.Question()
	got := f.harvest(&p, "github.com")
	if len(got) != 1 || got[0] != tcpip.AddrFrom4(ip) {
		t.Fatalf("harvest = %v, want [%s]", got, tcpip.AddrFrom4(ip))
	}
}

// TestHarvestTruncatedKeepsPartial verifies best-effort learning: a response
// cut mid-record (as TC-bit truncation produces) keeps the addresses that
// parsed before the cut.
func TestHarvestTruncatedKeepsPartial(t *testing.T) {
	f := newTestFilter(t, Config{})
	ip1 := [4]byte{151, 101, 1, 1}
	resp := buildResponse(t, 1, "docs.github.com.", []dnsmessage.Resource{
		aResource(t, "docs.github.com.", ip1),
		aResource(t, "docs.github.com.", [4]byte{151, 101, 2, 2}),
	})
	// Cut inside the second record's rdata.
	resp = resp[:len(resp)-2]

	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		t.Fatal(err)
	}
	p.Question()
	p.Question()
	got := f.harvest(&p, "docs.github.com")
	if len(got) != 1 || got[0] != tcpip.AddrFrom4(ip1) {
		t.Fatalf("harvest = %v, want just [%s] (the record before the cut)", got, tcpip.AddrFrom4(ip1))
	}
}

// TestHarvestCNAMELoop checks that a CNAME loop (a -> b -> a) terminates via the
// seen-set and depth cap and still collects the address reachable from the name.
func TestHarvestCNAMELoop(t *testing.T) {
	f := newTestFilter(t, Config{})
	ip := [4]byte{1, 2, 3, 4}
	resp := buildResponse(t, 1, "a.example.com.", []dnsmessage.Resource{
		cnameResource(t, "a.example.com.", "b.example.com."),
		cnameResource(t, "b.example.com.", "a.example.com."),
		aResource(t, "a.example.com.", ip),
	})
	var p dnsmessage.Parser
	p.Start(resp)
	p.Question()
	p.Question()
	got := f.harvest(&p, "a.example.com")
	found := false
	for _, a := range got {
		if a == tcpip.AddrFrom4(ip) {
			found = true
		}
	}
	if !found {
		t.Fatalf("harvest = %v, want to contain %s", got, tcpip.AddrFrom4(ip))
	}
}

func TestHarvestOffChainIgnored(t *testing.T) {
	f := newTestFilter(t, Config{})
	// CNAME chain that does NOT start at qname. The A record's owner is not
	// reachable from qname, so nothing should be learned.
	resp := buildResponse(t, 1, "docs.github.com.", []dnsmessage.Resource{
		cnameResource(t, "other.example.com.", "target.example.com."),
		aResource(t, "target.example.com.", [4]byte{1, 2, 3, 4}),
	})
	var p dnsmessage.Parser
	p.Start(resp)
	p.Question()
	p.Question()
	if got := f.harvest(&p, "docs.github.com"); len(got) != 0 {
		t.Fatalf("harvest learned off-chain addrs: %v", got)
	}
}

func TestHarvestDNAMEWithSynthesizedCNAME(t *testing.T) {
	f := newTestFilter(t, Config{})
	ip := [4]byte{1, 2, 3, 4}
	resp := buildResponse(t, 1, "a.sub.example.com.", []dnsmessage.Resource{
		{
			Header: dnsmessage.ResourceHeader{Name: mustName(t, "sub.example.com."), Type: dnsmessage.Type(39), Class: dnsmessage.ClassINET},
			Body:   &dnsmessage.UnknownResource{Type: dnsmessage.Type(39), Data: []byte{6, 't', 'a', 'r', 'g', 'e', 't', 3, 'n', 'e', 't', 0}},
		},
		cnameResource(t, "a.sub.example.com.", "a.target.net."),
		aResource(t, "a.target.net.", ip),
	})
	var p dnsmessage.Parser
	p.Start(resp)
	p.Question()
	p.Question()
	got := f.harvest(&p, "a.sub.example.com")
	if len(got) != 1 || got[0] != tcpip.AddrFrom4(ip) {
		t.Fatalf("harvest = %v, want [%s]", got, tcpip.AddrFrom4(ip))
	}
}

func TestPendingTableTrackConsume(t *testing.T) {
	clock := faketime.NewManualClock()
	var tbl pendingTable
	tbl.init(4)
	now := clock.NowMonotonic()
	key := pendingKey{server: tcpip.AddrFrom4([4]byte{8, 8, 8, 8}), clientPort: 5353, txID: 42}
	if !tbl.track(key, "a.example.com", dnsmessage.TypeA, now, now.Add(queryTTL)) {
		t.Fatal("track failed on empty table")
	}
	if !tbl.nonEmpty() {
		t.Error("nonEmpty=false after track")
	}
	// Wrong txID: miss.
	if tbl.consume(pendingKey{server: key.server, clientPort: key.clientPort, txID: 43}, "a.example.com", dnsmessage.TypeA, now) {
		t.Error("consumed with wrong txID")
	}
	if !tbl.consume(key, "a.example.com", dnsmessage.TypeA, now) {
		t.Fatal("consume failed for a live matching entry")
	}
	if tbl.nonEmpty() {
		t.Error("nonEmpty=true after consuming the only entry")
	}
}

// TestPendingTableWrongNameNotEvicted verifies that a response matching the
// key but not the question name (as an off-path spoofer who guessed the txID
// could send) does not evict the entry, so the genuine response still learns.
func TestPendingTableWrongNameNotEvicted(t *testing.T) {
	clock := faketime.NewManualClock()
	var tbl pendingTable
	tbl.init(4)
	now := clock.NowMonotonic()
	key := pendingKey{server: tcpip.AddrFrom4([4]byte{8, 8, 8, 8}), clientPort: 5353, txID: 42}
	tbl.track(key, "a.example.com", dnsmessage.TypeA, now, now.Add(queryTTL))
	if tbl.consume(key, "evil.example.com", dnsmessage.TypeA, now) {
		t.Error("consumed with wrong name")
	}
	if !tbl.consume(key, "a.example.com", dnsmessage.TypeA, now) {
		t.Error("wrong-name response evicted the entry: genuine response not consumed")
	}
}

func TestPendingTableExpiry(t *testing.T) {
	clock := faketime.NewManualClock()
	var tbl pendingTable
	tbl.init(4)
	now := clock.NowMonotonic()
	key := pendingKey{server: tcpip.AddrFrom4([4]byte{8, 8, 8, 8}), clientPort: 5353, txID: 1}
	tbl.track(key, "a.example.com", dnsmessage.TypeA, now, now.Add(queryTTL))
	later := now.Add(queryTTL * 2)
	if tbl.consume(key, "a.example.com", dnsmessage.TypeA, later) {
		t.Error("consumed an expired entry")
	}
}

func TestPendingTableStaleEntrySwept(t *testing.T) {
	clock := faketime.NewManualClock()
	var tbl pendingTable
	tbl.init(4)
	now := clock.NowMonotonic()
	key := pendingKey{server: tcpip.AddrFrom4([4]byte{8, 8, 8, 8}), clientPort: 5353, txID: 7}
	// Track a query that will never receive a matching response.
	tbl.track(key, "a.example.com", dnsmessage.TypeA, now, now.Add(queryTTL))
	if !tbl.nonEmpty() {
		t.Fatal("nonEmpty=false after track")
	}
	// Before expiry, a sweep must not remove the live entry.
	tbl.maybeSweep(now)
	if !tbl.nonEmpty() {
		t.Fatal("sweep removed a live (unexpired) entry")
	}
	// After expiry, a sweep reclaims it so the gate returns to zero even though
	// no response ever arrived.
	tbl.maybeSweep(now.Add(queryTTL + pendingSweepInterval + 1))
	if tbl.nonEmpty() {
		t.Error("stale (expired, unanswered) entry was not swept: inbound gate stuck open")
	}
}

// TestLearnedSetCap verifies the learned-IP set stops accepting new addresses
// at its cap (keeping the ones already learned) and reports hitting the cap
// exactly once, so a resolver returning unbounded addresses cannot grow the
// allowlist without limit.
func TestLearnedSetCap(t *testing.T) {
	var l learnedSet
	l.init(2)
	a1 := tcpip.AddrFrom4([4]byte{1, 1, 1, 1})
	a2 := tcpip.AddrFrom4([4]byte{2, 2, 2, 2})
	a3 := tcpip.AddrFrom4([4]byte{3, 3, 3, 3})

	if hitCap := l.addBatch([]tcpip.Address{a1, a2, a3}); !hitCap {
		t.Error("addBatch overflowing the cap should report hitCap=true")
	}
	if !l.contains(a1) || !l.contains(a2) {
		t.Error("addresses added before the cap must remain")
	}
	if l.contains(a3) {
		t.Error("address over the cap must not be learned")
	}
	// The cap is reported only once, so the operator warning does not repeat.
	if hitCap := l.addBatch([]tcpip.Address{a3}); hitCap {
		t.Error("hitCap must be reported only on the call that first fills the set")
	}
}

func TestPendingTableCapRefusesButKeepsLive(t *testing.T) {
	clock := faketime.NewManualClock()
	var tbl pendingTable
	tbl.init(2)
	now := clock.NowMonotonic()
	exp := now.Add(queryTTL)
	k1 := pendingKey{clientPort: 1, txID: 1}
	k2 := pendingKey{clientPort: 2, txID: 2}
	k3 := pendingKey{clientPort: 3, txID: 3}
	if !tbl.track(k1, "one", dnsmessage.TypeA, now, exp) || !tbl.track(k2, "two", dnsmessage.TypeA, now, exp) {
		t.Fatal("failed to fill table")
	}
	// Table full of live entries: a third must be refused (not evicting a live one).
	if tbl.track(k3, "three", dnsmessage.TypeA, now, exp) {
		t.Error("track accepted a third entry over a full table of live entries")
	}
	if !tbl.consume(k1, "one", dnsmessage.TypeA, now) {
		t.Error("live entry k1 was evicted")
	}
}
