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
	"fmt"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/egressallowlist"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	learnedSetCap     = 65536
	pendingTableCap   = 4096
	queryTTL          = 10 * time.Second
	maxAnswerRecords  = 64
	maxIPsPerResponse = 64
)

// IPv4 source-route option types from RFC 791.
const (
	ipv4OptionLooseSourceRoute  header.IPv4OptionType = 131
	ipv4OptionStrictSourceRoute header.IPv4OptionType = 137
)

// maxIPv6ExtHdrs limits extension-header parsing before dropping a packet.
const maxIPv6ExtHdrs = 8

const maxControlPayloadSize = 1280

// dropLogger limits per-packet logs to avoid flooding the sandbox log.
var dropLogger = log.BasicRateLimitedLogger(time.Minute)

// warnLogger rate-limits operational warnings (learned-set full, truncated DNS).
var warnLogger = log.BasicRateLimitedLogger(time.Minute)

// Config specifies the egress allowlist and query clock.
type Config struct {
	// Domains lists exact names or "*." patterns whose DNS answers are learned.
	Domains []string
	// IPs are statically allowed destinations, each an IP or CIDR (v4 or v6).
	IPs []string
	// Clock drives pending-query expiry. Required.
	Clock tcpip.Clock
}

// Filter holds a sandbox's egress policy and DNS state. Multiple NICs may use
// it concurrently.
type Filter struct {
	// Immutable after construction.
	staticExact map[tcpip.Address]struct{}
	staticNets  []tcpip.Subnet
	domains     egressallowlist.DomainMatcher
	clock       tcpip.Clock

	learned learnedSet
	pending pendingTable
}

// NewFilter validates cfg and constructs the shared policy state.
func NewFilter(cfg Config) (*Filter, error) {
	if cfg.Clock == nil {
		return nil, fmt.Errorf("egressfilter: Config.Clock is required")
	}
	dm, err := egressallowlist.NewDomainMatcher(cfg.Domains)
	if err != nil {
		return nil, err
	}
	exact, nets, err := parseStaticIPs(cfg.IPs)
	if err != nil {
		return nil, err
	}

	f := &Filter{
		staticExact: exact,
		staticNets:  nets,
		domains:     dm,
		clock:       cfg.Clock,
	}
	f.learned.init(learnedSetCap)
	f.pending.init(pendingTableCap)
	return f, nil
}

// verdict is the result of evaluating one egress packet.
type verdict int

const (
	verdictAllow verdict = iota
	// verdictDropNotAllowed: a well-formed IP packet to a destination that is
	// neither statically allowed nor learned.
	verdictDropNotAllowed
	// verdictDropMalformed: the packet could not be parsed as the protocol its
	// link header claims. Fail closed.
	verdictDropMalformed
	// verdictDropProto: an unknown/disallowed EtherType or a policy-blocked
	// packet (source routing).
	verdictDropProto
)

// parseStaticIPs splits normalized prefixes into exact addresses and subnets.
func parseStaticIPs(ips []string) (map[tcpip.Address]struct{}, []tcpip.Subnet, error) {
	prefixes, err := egressallowlist.ParseIPList(ips)
	if err != nil {
		return nil, nil, err
	}
	exact := make(map[tcpip.Address]struct{})
	var nets []tcpip.Subnet
	for _, p := range prefixes {
		if p.IsSingleIP() {
			exact[netipToAddr(p.Addr())] = struct{}{}
			continue
		}
		nets = append(nets, tcpip.AddressWithPrefix{
			Address:   netipToAddr(p.Addr()),
			PrefixLen: p.Bits(),
		}.Subnet())
	}
	return exact, nets, nil
}

// netipToAddr converts a netip.Addr to a tcpip.Address, unmapping v4-in-v6 so
// IPv4 addresses are always stored in 4-byte form.
func netipToAddr(a netip.Addr) tcpip.Address {
	a = a.Unmap()
	if a.Is4() {
		v := a.As4()
		return tcpip.AddrFrom4(v)
	}
	v := a.As16()
	return tcpip.AddrFrom16(v)
}

// allowedDst reports whether dst is statically allowed or has been learned.
func (f *Filter) allowedDst(dst tcpip.Address) bool {
	if _, ok := f.staticExact[dst]; ok {
		return true
	}
	if f.learned.contains(dst) {
		return true
	}
	for i := range f.staticNets {
		if f.staticNets[i].Contains(dst) {
			return true
		}
	}
	return false
}

// egressResult holds a verdict and, for allowed or blocked IP packets, the
// destination and transport protocol.
type egressResult struct {
	v       verdict
	dst     tcpip.Address
	l4proto uint8
}

// evaluate checks an outbound packet without modifying it.
func (f *Filter) evaluate(pkt *stack.PacketBuffer) egressResult {
	eth := pkt.LinkHeader().Slice()
	var wire tcpip.NetworkProtocolNumber
	if len(eth) >= header.EthernetMinimumSize {
		// Packet sockets control NetworkProtocolNumber, which may differ from
		// the wire EtherType.
		wire = header.Ethernet(eth).Type()
	} else {
		// Without a link header, use the IP version nibble.
		b, ok := f.firstByte(pkt)
		if !ok {
			return egressResult{v: verdictDropMalformed}
		}
		switch b >> 4 {
		case 4:
			wire = header.IPv4ProtocolNumber
		case 6:
			wire = header.IPv6ProtocolNumber
		default:
			return egressResult{v: verdictDropProto}
		}
	}

	switch wire {
	case header.ARPProtocolNumber:
		return egressResult{v: f.evalARP(pkt)}
	case header.IPv4ProtocolNumber:
		return f.evalV4(pkt)
	case header.IPv6ProtocolNumber:
		return f.evalV6(pkt)
	default:
		return egressResult{v: verdictDropProto}
	}
}

// firstByte reads the network header, or Data for packet-socket writes.
func (f *Filter) firstByte(pkt *stack.PacketBuffer) (byte, bool) {
	if nh := pkt.NetworkHeader().Slice(); len(nh) > 0 {
		return nh[0], true
	}
	if b, ok := pkt.Data().PullUp(1); ok {
		return b[0], true
	}
	return 0, false
}

// networkHeaderBytes returns at least n header bytes. Packet-socket writes
// leave the network header in Data.
func (f *Filter) networkHeaderBytes(pkt *stack.PacketBuffer, n int) ([]byte, bool) {
	if nh := pkt.NetworkHeader().Slice(); len(nh) >= n {
		return nh, true
	}
	if len(pkt.NetworkHeader().Slice()) == 0 {
		if b, ok := pkt.Data().PullUp(n); ok {
			return b, true
		}
	}
	return nil, false
}

// evalARP permits valid ARP packets with only Ethernet minimum-frame padding.
func (f *Filter) evalARP(pkt *stack.PacketBuffer) verdict {
	b, ok := f.networkHeaderBytes(pkt, header.ARPSize)
	if !ok {
		return verdictDropMalformed
	}
	if !header.ARP(b).IsValid() {
		return verdictDropMalformed
	}
	// Allow padding from the 28-byte ARP message to the Ethernet minimum.
	if total := len(pkt.NetworkHeader().Slice()) + pkt.Data().Size(); total > 46 {
		return verdictDropMalformed
	}
	return verdictAllow
}

func (f *Filter) evalV4(pkt *stack.PacketBuffer) egressResult {
	b, ok := f.networkHeaderBytes(pkt, header.IPv4MinimumSize)
	if !ok {
		return egressResult{v: verdictDropMalformed}
	}
	if header.IPVersion(b) != header.IPv4Version {
		return egressResult{v: verdictDropMalformed}
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < header.IPv4MinimumSize || ihl > header.IPv4MaximumHeaderSize {
		return egressResult{v: verdictDropMalformed}
	}
	if ihl > len(b) {
		b, ok = f.networkHeaderBytes(pkt, ihl)
		if !ok {
			return egressResult{v: verdictDropMalformed}
		}
	}
	h := header.IPv4(b)
	if ihl > header.IPv4MinimumSize {
		if !ipv4OptionsAllowed(b[header.IPv4MinimumSize:ihl]) {
			return egressResult{v: verdictDropProto}
		}
	}
	dst := h.DestinationAddress()
	proto := h.Protocol()
	if f.allowedDst(dst) {
		return egressResult{v: verdictAllow, dst: dst, l4proto: proto}
	}
	// Only link-local IGMP destinations are exempt. IGMPv2 reports to other
	// multicast groups require an allowlist entry.
	if proto == uint8(header.IGMPProtocolNumber) && header.IsV4LinkLocalMulticastAddress(dst) && f.igmpValid(pkt, h, ihl) {
		return egressResult{v: verdictAllow, dst: dst, l4proto: proto}
	}
	return egressResult{v: verdictDropNotAllowed, dst: dst, l4proto: proto}
}

// ipv4OptionsAllowed rejects malformed options and source routes, which could
// redirect an allowed destination to a blocked one.
func ipv4OptionsAllowed(opts header.IPv4Options) bool {
	iter := opts.MakeIterator()
	for {
		opt, done, err := iter.Next()
		if err != nil {
			return false
		}
		if done {
			return true
		}
		switch opt.Type() {
		case ipv4OptionLooseSourceRoute, ipv4OptionStrictSourceRoute:
			return false
		}
	}
}

func (f *Filter) evalV6(pkt *stack.PacketBuffer) egressResult {
	b, ok := f.networkHeaderBytes(pkt, header.IPv6MinimumSize)
	if !ok {
		return egressResult{v: verdictDropMalformed}
	}
	if header.IPVersion(b) != header.IPv6Version {
		return egressResult{v: verdictDropMalformed}
	}
	h := header.IPv6(b)
	dst := h.DestinationAddress()
	nh := h.NextHeader()

	upper, upperOffset, hbhOnly, routingSeen, ok := f.walkV6ExtHdrs(pkt, nh)
	if !ok {
		return egressResult{v: verdictDropMalformed}
	}
	if routingSeen {
		// Routing headers can redirect an allowed destination to a blocked one.
		return egressResult{v: verdictDropProto}
	}

	if f.allowedDst(dst) {
		return egressResult{v: verdictAllow, dst: dst, l4proto: upper}
	}

	// Exempt only link-local NDP/MLD traffic. MLD uses a Hop-by-Hop Router Alert
	// header before ICMPv6.
	if upper == uint8(header.ICMPv6ProtocolNumber) &&
		(header.IsV6LinkLocalMulticastAddress(dst) || header.IsV6LinkLocalUnicastAddress(dst)) &&
		(nh == uint8(header.ICMPv6ProtocolNumber) || hbhOnly) {
		if f.icmpv6ControlValid(pkt, h, upperOffset, hbhOnly) {
			return egressResult{v: verdictAllow, dst: dst, l4proto: upper}
		}
	}
	return egressResult{v: verdictDropNotAllowed, dst: dst, l4proto: upper}
}

func (f *Filter) igmpValid(pkt *stack.PacketBuffer, ip header.IPv4, offset int) bool {
	if ip.TTL() != header.IGMPTTL || !ip.IsChecksumValid() || int(ip.TotalLength()) != pkt.Size()-len(pkt.LinkHeader().Slice()) {
		return false
	}
	b, ok := f.controlPayload(pkt, offset)
	if !ok || len(b) < header.IGMPMinimumSize || checksum.Checksum(b, 0) != 0xffff {
		return false
	}
	switch header.IGMP(b).Type() {
	case header.IGMPv1MembershipReport, header.IGMPv2MembershipReport, header.IGMPLeaveGroup:
		return len(b) == header.IGMPMinimumSize
	case header.IGMPv3MembershipReport:
		return len(b) >= header.IGMPMinimumSize
	default:
		return false
	}
}

func (f *Filter) icmpv6ControlValid(pkt *stack.PacketBuffer, ip header.IPv6, offset int, hbhOnly bool) bool {
	if int(ip.PayloadLength())+header.IPv6MinimumSize != pkt.Size()-len(pkt.LinkHeader().Slice()) {
		return false
	}
	b, ok := f.controlPayload(pkt, offset)
	if !ok || len(b) < header.ICMPv6MinimumSize {
		return false
	}
	icmp := header.ICMPv6(b)
	if icmp.Code() != 0 || icmp.Checksum() != header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmp,
		Src:    ip.SourceAddress(),
		Dst:    ip.DestinationAddress(),
	}) {
		return false
	}
	switch icmp.Type() {
	case header.ICMPv6RouterSolicit:
		return ip.HopLimit() == header.NDPHopLimit && len(b) >= header.ICMPv6HeaderSize+header.NDPRSMinimumSize
	case header.ICMPv6NeighborSolicit:
		return ip.HopLimit() == header.NDPHopLimit && len(b) >= header.ICMPv6NeighborSolicitMinimumSize
	case header.ICMPv6NeighborAdvert:
		return ip.HopLimit() == header.NDPHopLimit && len(b) >= header.ICMPv6NeighborAdvertMinimumSize
	case header.ICMPv6MulticastListenerQuery, header.ICMPv6MulticastListenerReport, header.ICMPv6MulticastListenerDone:
		return hbhOnly && ip.HopLimit() == header.MLDHopLimit && len(b) >= header.ICMPv6HeaderSize+header.MLDMinimumSize
	case header.ICMPv6MulticastListenerV2Report:
		return hbhOnly && ip.HopLimit() == header.MLDHopLimit && len(b) >= header.ICMPv6HeaderSize+header.MLDv2ReportMinimumSize
	default:
		return false
	}
}

// walkV6ExtHdrs returns the upper-layer protocol and offset. It also reports
// whether only an 8-byte Hop-by-Hop header precedes ICMPv6 and whether any
// Routing header was seen. Traversal is bounded by maxIPv6ExtHdrs.
//
// PullUp avoids the buffer clone required by header.MakeIPv6PayloadIterator.
func (f *Filter) walkV6ExtHdrs(pkt *stack.PacketBuffer, nextHeader uint8) (upper uint8, upperOffset int, hbhOnly, routingSeen bool, ok bool) {
	const (
		hbh     = uint8(header.IPv6HopByHopOptionsExtHdrIdentifier)
		routing = uint8(header.IPv6RoutingExtHdrIdentifier)
		frag    = uint8(header.IPv6FragmentExtHdrIdentifier)
		dstOpts = uint8(header.IPv6DestinationOptionsExtHdrIdentifier)
		ah      = uint8(header.IPv6AuthenticationExtHdrIdentifier)
	)
	// Fast path: no extension headers.
	switch nextHeader {
	case hbh, routing, frag, dstOpts, ah:
	default:
		return nextHeader, header.IPv6MinimumSize, false, false, true
	}

	offset := header.IPv6MinimumSize
	cur := nextHeader
	extCount := 0
	for {
		if cur == routing {
			routingSeen = true
		}
		switch cur {
		case hbh, routing, dstOpts:
			hdr, ok := f.extHdrAt(pkt, offset, 2)
			if !ok {
				return 0, 0, false, false, false
			}
			// Length is in 8-octet units, not including the first 8 octets.
			hlen := (int(hdr[1]) + 1) * 8
			if cur == hbh && extCount == 0 && hlen == 8 && hdr[0] == uint8(header.ICMPv6ProtocolNumber) {
				hbhOnly = true
			} else {
				hbhOnly = false
			}
			offset += hlen
			cur = hdr[0]
		case ah:
			hdr, ok := f.extHdrAt(pkt, offset, 2)
			if !ok {
				return 0, 0, false, false, false
			}
			// AH length is in 4-octet units, minus 2.
			hlen := (int(hdr[1]) + 2) * 4
			offset += hlen
			cur = hdr[0]
			hbhOnly = false
		case frag:
			hdr, ok := f.extHdrAt(pkt, offset, 8)
			if !ok {
				return 0, 0, false, false, false
			}
			offset += 8
			cur = hdr[0]
			hbhOnly = false
		default:
			return cur, offset, hbhOnly, routingSeen, true
		}
		extCount++
		if extCount > maxIPv6ExtHdrs {
			return 0, 0, false, false, false
		}
	}
}

// extHdrAt reads n bytes at a network-layer offset. The bytes must lie wholly
// within NetworkHeader or Data.
func (f *Filter) extHdrAt(pkt *stack.PacketBuffer, offset, n int) ([]byte, bool) {
	nh := pkt.NetworkHeader().Slice()
	if len(nh) == 0 {
		// Packet-socket origin: the whole L3 packet is in Data.
		full, ok := pkt.Data().PullUp(offset + n)
		if !ok {
			return nil, false
		}
		return full[offset : offset+n], true
	}
	if offset < len(nh) {
		if offset+n <= len(nh) {
			return nh[offset : offset+n], true
		}
		// Reads spanning NetworkHeader and Data are unsupported.
		return nil, false
	}
	dataOff := offset - len(nh)
	b, ok := pkt.Data().PullUp(dataOff + n)
	if !ok {
		return nil, false
	}
	return b[dataOff : dataOff+n], true
}

func (f *Filter) controlPayload(pkt *stack.PacketBuffer, offset int) ([]byte, bool) {
	nh := pkt.NetworkHeader().Slice()
	if len(nh) == 0 {
		if offset > pkt.Data().Size() || pkt.Data().Size()-offset > maxControlPayloadSize {
			return nil, false
		}
		b, ok := pkt.Data().PullUp(pkt.Data().Size())
		if !ok {
			return nil, false
		}
		return b[offset:], true
	}
	if th := pkt.TransportHeader().Slice(); len(th) != 0 {
		if len(th)+pkt.Data().Size() > maxControlPayloadSize {
			return nil, false
		}
		if pkt.Data().Size() == 0 {
			return th, true
		}
		data, ok := pkt.Data().PullUp(pkt.Data().Size())
		if !ok {
			return nil, false
		}
		b := make([]byte, 0, len(th)+len(data))
		b = append(b, th...)
		return append(b, data...), true
	}
	dataOffset := offset - len(nh)
	if dataOffset < 0 || dataOffset > pkt.Data().Size() || pkt.Data().Size()-dataOffset > maxControlPayloadSize {
		return nil, false
	}
	b, ok := pkt.Data().PullUp(pkt.Data().Size())
	if !ok {
		return nil, false
	}
	return b[dataOffset:], true
}

// learnedSet holds DNS-learned addresses without expiry or eviction.
// It stops accepting new addresses at capacity.
type learnedSet struct {
	mu sync.RWMutex
	// m is protected by mu.
	m   map[tcpip.Address]struct{}
	cap int
	// full suppresses repeated capacity warnings. Protected by mu.
	full bool
}

func (l *learnedSet) init(capacity int) {
	l.m = make(map[tcpip.Address]struct{})
	l.cap = capacity
}

func (l *learnedSet) contains(addr tcpip.Address) bool {
	l.mu.RLock()
	_, ok := l.m[addr]
	l.mu.RUnlock()
	return ok
}

// addBatch inserts addresses up to capacity. It returns true only on the first
// attempt to exceed capacity.
func (l *learnedSet) addBatch(addrs []tcpip.Address) (hitCap bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, a := range addrs {
		if _, ok := l.m[a]; ok {
			continue
		}
		if len(l.m) >= l.cap {
			hitCap = !l.full
			l.full = true
			return hitCap
		}
		l.m[a] = struct{}{}
	}
	return false
}

func logDrop(res egressResult) {
	if res.dst.Len() == 0 {
		dropLogger.Infof("egressfilter: dropped egress packet (%s)", dropReason(res.v))
		return
	}
	if res.l4proto == uint8(header.UDPProtocolNumber) {
		dropLogger.Infof("egressfilter: dropped egress packet to %s (%s). If this is your DNS resolver, add it to --egress-allow-ips", res.dst, dropReason(res.v))
		return
	}
	dropLogger.Infof("egressfilter: dropped egress packet to %s (%s)", res.dst, dropReason(res.v))
}

func dropReason(v verdict) string {
	switch v {
	case verdictDropMalformed:
		return "malformed packet"
	case verdictDropProto:
		return "disallowed protocol or option"
	default:
		return "destination not in allowlist and not DNS-learned"
	}
}
