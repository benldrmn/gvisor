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
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/egressallowlist"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/header/parse"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// dnsPort is the well-known port for plain DNS over UDP.
const dnsPort = 53

// maxCNAMEChain bounds how deep a CNAME chain the harvester follows.
const maxCNAMEChain = 16

// pendingKey identifies an in-flight DNS query. Pinning all four fields raises
// the bar for off-path response spoofing to that of a normal resolver.
type pendingKey struct {
	// server is the DNS server address (destination of the query, source of the
	// response).
	server tcpip.Address
	// local is the query's source address (response destination address). A
	// Filter may be shared by multiple NICs, so the UDP port is not sufficient.
	local tcpip.Address
	// clientPort is the workload's UDP source port.
	clientPort uint16
	// txID is the DNS transaction ID.
	txID uint16
}

type pendingEntry struct {
	qName  string
	qType  dnsmessage.Type
	expiry tcpip.MonotonicTime
}

// pendingSweepInterval bounds how often expired entries are reclaimed by the
// lazy sweep, so the inbound-snoop gate returns to zero within one interval
// after the last live query expires.
const pendingSweepInterval = 10 * time.Second

// pendingTable tracks in-flight DNS queries whose names are on the allowlist.
// It is bounded. When full it refuses new entries rather than evicting live
// ones, so a query flood can only deny the workload its own future learning.
//
// count is maintained under mu but read locklessly by the inbound gate. It is
// always >= the number of live entries, so a positive count never misses a real
// response. It may transiently over-count expired-but-unswept entries, which
// maybeSweep reclaims within pendingSweepInterval.
type pendingTable struct {
	mu    sync.Mutex
	m     map[pendingKey]pendingEntry
	cap   int
	count atomicbitops.Int64
	// nextSweepNanos is the monotonic time (nanoseconds) of the next allowed
	// sweep, used to throttle maybeSweep without locking on every inbound packet.
	nextSweepNanos atomicbitops.Int64
}

func (t *pendingTable) init(capacity int) {
	t.m = make(map[pendingKey]pendingEntry)
	t.cap = capacity
}

// nonEmpty reports whether any query might be in flight. It is safe to call
// without holding mu.
func (t *pendingTable) nonEmpty() bool {
	return t.count.Load() > 0
}

// maybeSweep reclaims expired entries at most once per pendingSweepInterval. It
// is called from the inbound path so that, even if a tracked query never gets a
// matching response, count (and thus the snoop gate) returns to zero shortly
// after the query's TTL, restoring the idle fast path.
func (t *pendingTable) maybeSweep(now tcpip.MonotonicTime) {
	if t.count.Load() == 0 {
		return
	}
	nowNanos := int64(now.Sub(tcpip.MonotonicTime{}))
	if nowNanos < t.nextSweepNanos.Load() {
		return
	}
	t.mu.Lock()
	if nowNanos >= t.nextSweepNanos.Load() {
		t.nextSweepNanos.Store(nowNanos + pendingSweepInterval.Nanoseconds())
		t.sweepExpiredLocked(now)
	}
	t.mu.Unlock()
}

// track records a pending query. It returns true if the entry was inserted
// (or refreshed), false if the table was full. now is the current monotonic
// time. Expired entries are swept lazily on a full table.
func (t *pendingTable) track(key pendingKey, qName string, qType dnsmessage.Type, now, expiry tcpip.MonotonicTime) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, existing := t.m[key]
	if !existing && len(t.m) >= t.cap {
		t.sweepExpiredLocked(now)
		if len(t.m) >= t.cap {
			return false
		}
	}
	t.m[key] = pendingEntry{qName: qName, qType: qType, expiry: expiry}
	if !existing {
		t.count.Add(1)
	}
	return true
}

// consume removes the entry matching key, qName, and qType, reporting whether it
// was present and live (non-expired). An entry whose name does not match is
// left in place: an off-path spoofer who guesses the key but not the query
// name must not be able to evict the entry before the genuine response
// arrives.
func (t *pendingTable) consume(key pendingKey, qName string, qType dnsmessage.Type, now tcpip.MonotonicTime) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, present := t.m[key]
	if !present || e.qName != qName || e.qType != qType {
		return false
	}
	delete(t.m, key)
	t.count.Add(-1)
	return !now.After(e.expiry)
}

func (t *pendingTable) sweepExpiredLocked(now tcpip.MonotonicTime) {
	for k, e := range t.m {
		if now.After(e.expiry) {
			delete(t.m, k)
			t.count.Add(-1)
		}
	}
}

// trackDNSQuery records an outbound plain UDP DNS query for an allowlisted
// name so the matching response can be learned from. Queries for other names
// are not tracked: they grant no egress by themselves, but they are forwarded
// so a name resolving into the static IP allowlist still works. It never
// mutates pkt.
func (f *Filter) trackDNSQuery(pkt *stack.PacketBuffer, dst tcpip.Address, l4proto uint8) {
	if l4proto != uint8(header.UDPProtocolNumber) || f.domains.Empty() {
		return
	}
	transport := pkt.TransportHeader().Slice()
	if len(transport) < header.UDPMinimumSize {
		return
	}
	udp := header.UDP(transport)
	if udp.DestinationPort() != dnsPort {
		return
	}
	sz := pkt.Data().Size()
	if sz == 0 {
		return
	}
	payload, ok := pkt.Data().PullUp(sz)
	if !ok {
		return
	}
	qName, qType, txID, ok := parseDNSQuery(payload)
	if !ok || !f.domains.Match(qName) {
		return
	}
	local := networkSrc(pkt.NetworkProtocolNumber, pkt.NetworkHeader().Slice())
	if local.Len() == 0 {
		return
	}
	now := f.clock.NowMonotonic()
	key := pendingKey{server: dst, local: local, clientPort: udp.SourcePort(), txID: txID}
	f.pending.track(key, qName, qType, now, now.Add(queryTTL))
}

// snoopInbound inspects an inbound packet for a DNS response matching a pending
// query and, if found, learns its addresses. It never mutates or drops pkt and
// never panics. Learning happens before the caller delivers the packet up, so
// the workload's resolve-then-connect sequence cannot race the learner.
func (f *Filter) snoopInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	switch protocol {
	case header.IPv4ProtocolNumber, header.IPv6ProtocolNumber:
	default:
		return
	}

	// Clone the packet so the mutating parse helpers never disturb the original
	// that will be delivered up the stack.
	clone := pkt.TrimmedNetworkClone()
	defer clone.DecRef()

	var l4 tcpip.TransportProtocolNumber
	switch protocol {
	case header.IPv4ProtocolNumber:
		if !parse.IPv4(clone) {
			return
		}
		ipHdr := header.IPv4(clone.NetworkHeader().Slice())
		if !clone.RXChecksumValidated && !ipHdr.IsChecksumValid() {
			return
		}
		// A fragmented response is not reassembled here, so its payload cannot be
		// read as DNS; skip it. The address is simply not learned (fail closed).
		if ipHdr.FragmentOffset() != 0 || ipHdr.Flags()&header.IPv4FlagMoreFragments != 0 {
			return
		}
		l4 = tcpip.TransportProtocolNumber(ipHdr.Protocol())
	case header.IPv6ProtocolNumber:
		var (
			fragOffset uint16
			fragMore   bool
			ok         bool
		)
		l4, _, fragOffset, fragMore, ok = parse.IPv6(clone)
		if !ok {
			return
		}
		if fragOffset != 0 || fragMore {
			return
		}
	}
	if l4 != header.UDPProtocolNumber {
		return
	}
	if !parse.UDP(clone) {
		return
	}
	udp := header.UDP(clone.TransportHeader().Slice())
	if udp.SourcePort() != dnsPort {
		return
	}

	src := networkSrc(protocol, clone.NetworkHeader().Slice())
	dst := networkDst(protocol, clone.NetworkHeader().Slice())
	if src.Len() == 0 || dst.Len() == 0 || clone.Data().Size() > int(^uint16(0)) {
		return
	}
	lengthValid, checksumValid := header.UDPValid(
		udp,
		func() uint16 { return clone.Data().Checksum() },
		uint16(clone.Data().Size()),
		protocol,
		src,
		dst,
		clone.RXChecksumValidated,
	)
	if !lengthValid || !checksumValid {
		return
	}

	data := clone.Data()
	sz := data.Size()
	// Read only the bytes the UDP length field claims, not trailing padding or
	// anything a sender appended past the datagram, so the snoop sees exactly
	// what the UDP layer will deliver.
	if udpLen := int(udp.Length()); udpLen >= header.UDPMinimumSize && udpLen-header.UDPMinimumSize < sz {
		sz = udpLen - header.UDPMinimumSize
	}
	if sz == 0 {
		return
	}
	payload, ok := data.PullUp(sz)
	if !ok {
		return
	}

	f.learnFromResponse(payload, src, dst, udp.DestinationPort())
}

// learnFromResponse parses a DNS response, verifies it against a pending query,
// and adds any learned addresses to the learned set. server/clientPort are read
// from the packet. The transaction ID and question come from the payload.
func (f *Filter) learnFromResponse(payload []byte, server, local tcpip.Address, clientPort uint16) {
	var p dnsmessage.Parser
	hdr, err := p.Start(payload)
	if err != nil {
		return
	}
	if !hdr.Response || hdr.OpCode != 0 {
		return
	}

	// Read the single question to recover the queried name and pin the txID.
	q, err := p.Question()
	if err != nil {
		return
	}
	if _, err := p.Question(); err != dnsmessage.ErrSectionDone {
		// Real responses echo exactly one question.
		return
	}
	qName := egressallowlist.NormalizeName(q.Name.String())
	if q.Class != dnsmessage.ClassINET || (q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA) {
		return
	}

	key := pendingKey{server: server, local: local, clientPort: clientPort, txID: hdr.ID}
	if !f.pending.consume(key, qName, q.Type, f.clock.NowMonotonic()) {
		return
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		return
	}
	if hdr.Truncated {
		warnLogger.Warningf("egressfilter: DNS response for %q was truncated (TC bit), so its TCP-retried addresses will not be learned", qName)
		// Still learn best-effort from any answers present before truncation.
	}

	ips := f.harvest(&p, qName)
	if len(ips) == 0 {
		return
	}
	if f.learned.addBatch(ips) {
		warnLogger.Warningf("egressfilter: learned-IP set is full, no further DNS-learned egress will be allowed")
	}
}

// harvest walks the ANSWER section, collecting A/AAAA addresses whose owner name
// is reachable from qName through this response's CNAME chain. Authority and
// additional sections are never read. It is bounded in records, IPs, and chain
// depth, and never panics. Learning is best-effort: a parse error mid-section
// (e.g. a TC-truncated response cut inside a record) keeps the records already
// collected.
func (f *Filter) harvest(p *dnsmessage.Parser, qName string) []tcpip.Address {
	type addrList []tcpip.Address
	addrs := make(map[string]addrList)
	cnames := make(map[string]string)

answers:
	for i := 0; i < maxAnswerRecords; i++ {
		h, err := p.AnswerHeader()
		if err != nil {
			// Includes ErrSectionDone.
			break
		}
		if h.Class != dnsmessage.ClassINET {
			if err := p.SkipAnswer(); err != nil {
				break
			}
			continue
		}
		owner := egressallowlist.NormalizeName(h.Name.String())
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				break answers
			}
			addrs[owner] = append(addrs[owner], tcpip.AddrFrom4(r.A))
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				break answers
			}
			addrs[owner] = append(addrs[owner], netipToAddr(netip.AddrFrom16(r.AAAA)))
		case dnsmessage.TypeCNAME:
			r, err := p.CNAMEResource()
			if err != nil {
				break answers
			}
			cnames[owner] = egressallowlist.NormalizeName(r.CNAME.String())
		default:
			if err := p.SkipAnswer(); err != nil {
				break answers
			}
		}
	}

	// Walk the chain from qName, collecting the addresses of every reachable
	// name. Loop-safe via the seen set and the depth cap.
	var out []tcpip.Address
	seen := make(map[string]struct{})
	cur := qName
	for depth := 0; depth < maxCNAMEChain; depth++ {
		for _, a := range addrs[cur] {
			if len(out) >= maxIPsPerResponse {
				return out
			}
			out = append(out, a)
		}
		next, ok := cnames[cur]
		if !ok {
			break
		}
		if _, dup := seen[cur]; dup {
			break
		}
		seen[cur] = struct{}{}
		cur = next
	}
	return out
}

// parseDNSQuery extracts the normalized question name and transaction ID from
// a DNS query. It requires a single question of class IN and type A or AAAA,
// the only kind that can yield learnable addresses. ok is false on any
// malformation.
func parseDNSQuery(payload []byte) (qName string, qType dnsmessage.Type, txID uint16, ok bool) {
	var p dnsmessage.Parser
	hdr, err := p.Start(payload)
	if err != nil {
		return "", 0, 0, false
	}
	if hdr.Response || hdr.OpCode != 0 {
		return "", 0, 0, false
	}
	q, err := p.Question()
	if err != nil {
		return "", 0, 0, false
	}
	if _, err := p.Question(); err != dnsmessage.ErrSectionDone {
		return "", 0, 0, false
	}
	if q.Class != dnsmessage.ClassINET {
		return "", 0, 0, false
	}
	if q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA {
		return "", 0, 0, false
	}
	return egressallowlist.NormalizeName(q.Name.String()), q.Type, hdr.ID, true
}

// networkSrc returns the source address from a parsed network header.
func networkSrc(protocol tcpip.NetworkProtocolNumber, netHdr []byte) tcpip.Address {
	switch protocol {
	case header.IPv4ProtocolNumber:
		if len(netHdr) < header.IPv4MinimumSize {
			return tcpip.Address{}
		}
		return header.IPv4(netHdr).SourceAddress()
	case header.IPv6ProtocolNumber:
		if len(netHdr) < header.IPv6MinimumSize {
			return tcpip.Address{}
		}
		return header.IPv6(netHdr).SourceAddress()
	}
	return tcpip.Address{}
}

// networkDst returns the destination address from a parsed network header.
func networkDst(protocol tcpip.NetworkProtocolNumber, netHdr []byte) tcpip.Address {
	switch protocol {
	case header.IPv4ProtocolNumber:
		if len(netHdr) >= header.IPv4MinimumSize {
			return header.IPv4(netHdr).DestinationAddress()
		}
	case header.IPv6ProtocolNumber:
		if len(netHdr) >= header.IPv6MinimumSize {
			return header.IPv6(netHdr).DestinationAddress()
		}
	}
	return tcpip.Address{}
}
