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

const dnsPort = 53

const maxCNAMEChain = 16

// pendingKey identifies an in-flight DNS query.
type pendingKey struct {
	// server is the DNS server address.
	server tcpip.Address
	// local is the query's source address, needed to distinguish NICs sharing
	// a Filter.
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

// pendingSweepInterval is the minimum interval between expiry sweeps.
const pendingSweepInterval = 10 * time.Second

// pendingTable tracks queries for allowed names. When full, it refuses new
// queries without evicting live ones.
type pendingTable struct {
	mu sync.Mutex
	// m is protected by mu.
	m   map[pendingKey]pendingEntry
	cap int
	// count includes expired entries until swept. Updated under mu and read
	// atomically to skip DNS parsing when no queries are pending.
	count atomicbitops.Int64
	// nextSweepNanos throttles expiry sweeps without taking mu on every packet.
	nextSweepNanos atomicbitops.Int64
}

func (t *pendingTable) init(capacity int) {
	t.m = make(map[pendingKey]pendingEntry)
	t.cap = capacity
}

// nonEmpty reports whether queries may be pending without taking mu.
func (t *pendingTable) nonEmpty() bool {
	return t.count.Load() > 0
}

// maybeSweep reclaims expired entries at most once per pendingSweepInterval.
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

// track inserts or refreshes a query, returning false if the table is full.
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

// consume removes a matching query and reports whether it was unexpired.
// Mismatched questions leave the entry available for a valid response.
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

// trackDNSQuery records an allowed UDP DNS query without modifying pkt.
// Queries for other names are forwarded without enabling learning.
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

// snoopInbound learns addresses from responses to pending queries without
// modifying pkt.
//
// Preconditions: rxChecksumValidated matches the receiving NIC's checksum
// offload decision.
func (f *Filter) snoopInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer, rxChecksumValidated bool) {
	switch protocol {
	case header.IPv4ProtocolNumber, header.IPv6ProtocolNumber:
	default:
		return
	}

	// Parse a clone to preserve the original packet for the stack.
	clone := pkt.TrimmedNetworkClone()
	defer clone.DecRef()

	var l4 tcpip.TransportProtocolNumber
	switch protocol {
	case header.IPv4ProtocolNumber:
		if !parse.IPv4(clone) {
			return
		}
		ipHdr := header.IPv4(clone.NetworkHeader().Slice())
		if !rxChecksumValidated && !ipHdr.IsChecksumValid() {
			return
		}
		// Fragmented responses require reassembly before DNS parsing.
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
		rxChecksumValidated,
	)
	if !lengthValid || !checksumValid {
		return
	}

	data := clone.Data()
	sz := data.Size()
	// Ignore bytes past the UDP length, matching delivery to the socket.
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

// learnFromResponse adds addresses from a response matching a pending query.
func (f *Filter) learnFromResponse(payload []byte, server, local tcpip.Address, clientPort uint16) {
	var p dnsmessage.Parser
	hdr, err := p.Start(payload)
	if err != nil {
		return
	}
	if !hdr.Response || hdr.OpCode != 0 {
		return
	}

	q, err := p.Question()
	if err != nil {
		return
	}
	if _, err := p.Question(); err != dnsmessage.ErrSectionDone {
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
		// Learn any complete answers before the truncation.
	}

	ips := f.harvest(&p, qName)
	if len(ips) == 0 {
		return
	}
	if f.learned.addBatch(ips) {
		warnLogger.Warningf("egressfilter: learned-IP set is full, no further DNS-learned egress will be allowed")
	}
}

// harvest collects A/AAAA answers reachable from qName through CNAMEs.
// It ignores authority and additional sections and keeps complete records if
// parsing fails later in the answer section.
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

	// Follow CNAMEs with a depth limit and cycle detection.
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

// parseDNSQuery accepts a single IN A/AAAA question and returns its normalized
// name, type, and transaction ID.
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
