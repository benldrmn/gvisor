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
	"encoding/binary"
	"net/netip"
	"os"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}

// --- Static IP set ---

func TestStaticIPSet(t *testing.T) {
	f := newTestFilter(t, Config{IPs: []string{"8.8.8.8", "10.0.0.0/8", "2001:db8::1", "2001:4860::/32"}})
	allow := []string{"8.8.8.8", "10.1.2.3", "10.255.255.255", "2001:db8::1", "2001:4860:1::99"}
	deny := []string{"8.8.4.4", "11.0.0.1", "2001:db8::2", "2001:4861::1"}
	for _, s := range allow {
		if !f.allowedDst(mustAddr(t, s)) {
			t.Errorf("allowedDst(%s) = false, want true", s)
		}
	}
	for _, s := range deny {
		if f.allowedDst(mustAddr(t, s)) {
			t.Errorf("allowedDst(%s) = true, want false", s)
		}
	}
}

func TestNewFilterRejectsBadIPs(t *testing.T) {
	for _, ip := range []string{"not-an-ip", "8.8.8.8/40", "fe80::1%eth0", "999.1.1.1"} {
		if _, err := NewFilter(Config{IPs: []string{ip}, Clock: faketime.NewManualClock()}); err == nil {
			t.Errorf("NewFilter accepted bad IP %q", ip)
		}
	}
}

// --- Decision table via evaluate() over crafted packets ---

func TestEvaluateDecisionTable(t *testing.T) {
	f := newTestFilter(t, Config{IPs: []string{"93.184.216.34", "2606:2800:220::1"}})

	type tc struct {
		name string
		pkt  *stack.PacketBuffer
		want verdict
	}
	cases := []tc{
		{"v4 allowed dst", ethV4(t, [4]byte{93, 184, 216, 34}, 6, nil), verdictAllow},
		{"v4 denied dst", ethV4(t, [4]byte{1, 2, 3, 4}, 6, nil), verdictDropNotAllowed},
		{"v6 allowed dst", ethV6(t, mustAddr(t, "2606:2800:220::1"), 6, nil), verdictAllow},
		{"v6 denied dst", ethV6(t, mustAddr(t, "2606:2800:220::2"), 6, nil), verdictDropNotAllowed},
		// ICMP echo has no control-traffic exemption (unlike IGMP/NDP/MLD), so
		// a ping to a blocked destination is dropped like any other egress.
		{"v4 icmp echo denied dst", ethV4ICMPEcho(t, [4]byte{1, 2, 3, 4}), verdictDropNotAllowed},
		// A Routing extension header can redirect a packet with an allowed
		// destination onward to a blocked one, so it is dropped even though the
		// destination here is allowlisted (the v6 twin of the source-route case).
		{"v6 routing header to allowed dst", ethV6WithRouting(t, mustAddr(t, "2606:2800:220::1")), verdictDropProto},
		{"arp oversized", ethARP(t, true), verdictDropMalformed},
		{"unknown ethertype", ethFrame(t, 0x9999, make([]byte, 20), true), verdictDropProto},
		{"ipv4 mislabeled as arp carrying ip", arpEtherTypeCarryingIPv4(t, [4]byte{1, 2, 3, 4}), verdictDropMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer c.pkt.DecRef()
			if got := f.evaluate(c.pkt).v; got != c.want {
				t.Errorf("evaluate = %v, want %v", got, c.want)
			}
		})
	}
}

// TestOnLinkControlTrafficExemptFromDestinationAllowlist checks the exemption
// for control traffic needed to operate the link: ARP, IPv6 neighbor discovery,
// and IGMP/MLD membership to link-local control groups. The exemption is
// protocol-specific (a non-control protocol to the same address is still
// dropped) and bounded by destination scope, not by origin, so it is exercised
// here with workload-shaped (packet-socket) frames.
func TestOnLinkControlTrafficExemptFromDestinationAllowlist(t *testing.T) {
	f := newTestFilter(t, Config{IPs: []string{"9.9.9.9", "2001:db8::1"}})

	igmp := make([]byte, header.IGMPMinimumSize)
	header.IGMP(igmp).SetType(header.IGMPv2MembershipReport)

	neighborSolicit := make([]byte, header.ICMPv6NeighborSolicitMinimumSize)
	header.ICMPv6(neighborSolicit).SetType(header.ICMPv6NeighborSolicit)

	mldReport := make([]byte, header.ICMPv6MinimumSize)
	header.ICMPv6(mldReport).SetType(header.ICMPv6MulticastListenerV2Report)

	for _, tc := range []struct {
		name string
		pkt  *stack.PacketBuffer
		want verdict
	}{
		{"arp", ethARP(t, false), verdictAllow},
		{"igmp", ethV4(t, [4]byte{224, 0, 0, 1}, uint8(header.IGMPProtocolNumber), igmp), verdictAllow},
		{"neighbor discovery", ethV6(t, mustAddr(t, "ff02::1:ff00:1"), uint8(header.ICMPv6ProtocolNumber), neighborSolicit), verdictAllow},
		{"multicast listener discovery", ethV6(t, mustAddr(t, "ff02::16"), uint8(header.ICMPv6ProtocolNumber), mldReport), verdictAllow},
		{"multicast UDP data", ethV4(t, [4]byte{224, 0, 0, 1}, uint8(header.UDPProtocolNumber), nil), verdictDropNotAllowed},
		{"link-local TCP data", ethV6(t, mustAddr(t, "fe80::1"), uint8(header.TCPProtocolNumber), nil), verdictDropNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer tc.pkt.DecRef()
			if got := f.evaluate(tc.pkt).v; got != tc.want {
				t.Errorf("evaluate = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestControlTrafficToRoutableDestinationNotExempt is the security regression
// for the control-traffic exemption: a permitted control protocol/type does not
// grant egress to a routable (non-link-local) destination. A workload with raw
// or packet sockets could otherwise craft an IGMP or ICMPv6 message to a global
// multicast group and use it as an egress channel that leaves the segment.
func TestControlTrafficToRoutableDestinationNotExempt(t *testing.T) {
	f := newTestFilter(t, Config{IPs: []string{"9.9.9.9"}})

	igmp := make([]byte, header.IGMPMinimumSize)
	header.IGMP(igmp).SetType(header.IGMPv2MembershipReport)

	neighborSolicit := make([]byte, header.ICMPv6NeighborSolicitMinimumSize)
	header.ICMPv6(neighborSolicit).SetType(header.ICMPv6NeighborSolicit)

	for _, tc := range []struct {
		name string
		pkt  *stack.PacketBuffer
	}{
		{"igmp to routable multicast", ethV4(t, [4]byte{239, 1, 2, 3}, uint8(header.IGMPProtocolNumber), igmp)},
		{"icmpv6 to global multicast", ethV6(t, mustAddr(t, "ff0e::1"), uint8(header.ICMPv6ProtocolNumber), neighborSolicit)},
		{"icmpv6 to global unicast", ethV6(t, mustAddr(t, "2001:db8::99"), uint8(header.ICMPv6ProtocolNumber), neighborSolicit)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer tc.pkt.DecRef()
			if got := f.evaluate(tc.pkt).v; got != verdictDropNotAllowed {
				t.Errorf("control traffic to routable dst: evaluate = %v, want drop", got)
			}
		})
	}
}

// TestPacketSocketBypassClosed is the key security regression: a packet-socket
// frame whose NetworkHeader is empty (L3 sits in Data) and whose EtherType
// claims IPv4 must still have its destination filtered from the Data bytes.
func TestPacketSocketBypassClosed(t *testing.T) {
	f := newTestFilter(t, Config{IPs: []string{"9.9.9.9"}})

	// Denied destination in a packet-socket-shaped frame is dropped.
	denied := ethV4Cooked(t, [4]byte{1, 2, 3, 4})
	defer denied.DecRef()
	if got := f.evaluate(denied).v; got != verdictDropNotAllowed {
		t.Errorf("packet-socket denied dst: evaluate = %v, want drop", got)
	}
	if nh := denied.NetworkHeader().Slice(); len(nh) != 0 {
		t.Fatalf("test setup wrong: NetworkHeader should be empty, got %d bytes", len(nh))
	}

	// Allowed destination in the same shape passes (proves we actually read
	// the Data, not that we drop everything).
	allowed := ethV4Cooked(t, [4]byte{9, 9, 9, 9})
	defer allowed.DecRef()
	if got := f.evaluate(allowed).v; got != verdictAllow {
		t.Errorf("packet-socket allowed dst: evaluate = %v, want allow", got)
	}
}

// TestSourceRouteDropped verifies that an IPv4 packet to an allowed destination
// carrying a loose source-route option is dropped.
func TestSourceRouteDropped(t *testing.T) {
	f := newTestFilter(t, Config{IPs: []string{"9.9.9.9"}})
	pkt := ethV4WithOptions(t, [4]byte{9, 9, 9, 9}, []byte{
		byte(ipv4OptionLooseSourceRoute), 7, 4, // LSRR, len 7, pointer
		4, 3, 2, 1, // one route entry
		0, // end-of-list padding to a 4-byte boundary
	})
	defer pkt.DecRef()
	if got := f.evaluate(pkt).v; got != verdictDropProto {
		t.Errorf("LSRR to allowed dst: evaluate = %v, want drop(proto)", got)
	}
}

// --- IPv6 NDP ---

// TestNeighborAdvertAllowedNetstackOrigin checks that a solicited Neighbor
// Advertisement in netstack's own packet shape is allowed. Unlike NS/RS/MLD,
// netstack builds an NA with the ICMPv6 message in the TransportHeader and Data
// empty, so the type byte must be read from there.
func TestNeighborAdvertAllowedNetstackOrigin(t *testing.T) {
	f := newTestFilter(t, Config{IPs: []string{"9.9.9.9"}}) // NA's dst is not in this list
	dst := mustAddr(t, "fe80::1")                           // the solicitor's link-local address
	src := mustAddr(t, "fe80::2")                           // the sandbox's own link-local address
	pkt := netstackV6NeighborAdvert(t, src, dst)
	defer pkt.DecRef()
	if got := f.evaluate(pkt).v; got != verdictAllow {
		t.Errorf("netstack-origin solicited NA to link-local dst: evaluate = %v, want allow", got)
	}
}

// TestNeighborAdvertPacketSocketTransportHeaderIgnored checks that for a
// packet-socket-origin packet (empty NetworkHeader), icmpv6Type reads the type
// from Data, not from a TransportHeader: a workload could otherwise forge a
// TransportHeader claiming an allowed type to bypass the type check.
func TestNeighborAdvertPacketSocketTransportHeaderIgnored(t *testing.T) {
	f := newTestFilter(t, Config{IPs: []string{"9.9.9.9"}})
	dst := mustAddr(t, "fe80::1")

	icmp := make([]byte, header.ICMPv6MinimumSize)
	icmp[0] = byte(header.ICMPv6RouterAdvert) // Data claims a disallowed type.
	eth := make([]byte, header.EthernetMinimumSize)
	binary.BigEndian.PutUint16(eth[12:14], 0x86dd)
	frame := append(eth, buildV6(dst, uint8(header.ICMPv6ProtocolNumber), icmp)...)

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: 1, // room for the forged TransportHeader push below
		Payload:            buffer.MakeWithData(frame),
	})
	defer pkt.DecRef()
	if _, ok := pkt.LinkHeader().Consume(header.EthernetMinimumSize); !ok {
		t.Fatal("failed to consume link header")
	}
	if nh := pkt.NetworkHeader().Slice(); len(nh) != 0 {
		t.Fatalf("test setup wrong: NetworkHeader should be empty (packet-socket shape), got %d bytes", len(nh))
	}
	pkt.TransportHeader().Push(1)[0] = byte(header.ICMPv6NeighborSolicit) // TransportHeader claims an allowed type.

	if got := f.evaluate(pkt).v; got != verdictDropNotAllowed {
		t.Errorf("packet-socket ICMPv6 with forged TransportHeader: evaluate = %v, want drop (must read Data, not TransportHeader)", got)
	}
}

// netstackV6NeighborAdvert builds a solicited Neighbor Advertisement in the
// exact shape netstack's own IPv6 endpoint constructs one: NetworkHeader
// parsed, ICMPv6 message in TransportHeader, Data empty.
func netstackV6NeighborAdvert(t *testing.T, src, dst tcpip.Address) *stack.PacketBuffer {
	t.Helper()
	naSize := header.ICMPv6NeighborAdvertMinimumSize
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.EthernetMinimumSize + header.IPv6MinimumSize + naSize,
	})
	icmp := header.ICMPv6(pkt.TransportHeader().Push(naSize))
	icmp.SetType(header.ICMPv6NeighborAdvert)
	na := header.NDPNeighborAdvert(icmp.MessageBody())
	na.SetSolicitedFlag(true)
	na.SetTargetAddress(src)
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{Header: icmp, Src: src, Dst: dst}))

	ip := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(naSize),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          255,
		SrcAddr:           src,
		DstAddr:           dst,
	})
	pkt.NetworkProtocolNumber = header.IPv6ProtocolNumber
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	eth.Encode(&header.EthernetFields{Type: header.IPv6ProtocolNumber})
	return pkt
}

// --- End-to-end through the Endpoint + channel ---

func TestWritePacketsFiltersBatch(t *testing.T) {
	f := newTestFilter(t, Config{IPs: []string{"9.9.9.9"}})
	child := channel.New(16, 1500, "")
	defer child.Close()
	ep := New(child, f)

	pkts := []*stack.PacketBuffer{
		ethV4(t, [4]byte{9, 9, 9, 9}, 6, nil), // allow
		ethV4(t, [4]byte{1, 1, 1, 1}, 6, nil), // drop
		ethV4(t, [4]byte{9, 9, 9, 9}, 6, nil), // allow
	}
	// The caller always retains ownership of every packet (channel.Write clones
	// what it queues), so DecRef them all at the end.
	defer func() {
		for _, p := range pkts {
			p.DecRef()
		}
	}()

	var list stack.PacketBufferList
	for _, p := range pkts {
		list.PushBack(p)
	}
	n, err := ep.WritePackets(list)
	if err != nil {
		t.Fatalf("WritePackets: %v", err)
	}
	if n != len(pkts) {
		t.Errorf("WritePackets returned %d, want %d (drops count as sent)", n, len(pkts))
	}
	wantQueued := 2
	if got := child.NumQueued(); got != wantQueued {
		t.Errorf("child queued %d packets, want %d", got, wantQueued)
	}
	child.Drain() // DecRefs the channel's clones of the allowed packets.
}

func TestWritePacketsAllAllowedZeroDrop(t *testing.T) {
	f := newTestFilter(t, Config{IPs: []string{"9.9.9.9"}})
	child := channel.New(16, 1500, "")
	defer child.Close()
	ep := New(child, f)

	var pkts []*stack.PacketBuffer
	var list stack.PacketBufferList
	for i := 0; i < 3; i++ {
		p := ethV4(t, [4]byte{9, 9, 9, 9}, 6, nil)
		pkts = append(pkts, p)
		list.PushBack(p)
	}
	defer func() {
		for _, p := range pkts {
			p.DecRef()
		}
	}()
	if _, err := ep.WritePackets(list); err != nil {
		t.Fatalf("WritePackets: %v", err)
	}
	if got := child.NumQueued(); got != 3 {
		t.Errorf("child queued %d, want 3", got)
	}
	child.Drain()
}

// TestLearnFlow drives a full resolve-then-connect: an outbound query to an allowed
// resolver, an inbound response, and then egress to the learned address.
func TestLearnFlow(t *testing.T) {
	clock := faketime.NewManualClock()
	f := newTestFilter(t, Config{
		Domains: []string{"docs.github.com"},
		IPs:     []string{"8.8.8.8"},
		Clock:   clock,
	})
	child := channel.New(16, 1500, "")
	defer child.Close()
	ep := New(child, f)

	learnedIP := [4]byte{151, 101, 1, 1}

	// 1. Outbound DNS query to the allowed resolver.
	query := buildQuery(t, 0xABCD, "docs.github.com.", dnsmessage.TypeA)
	qpkt := netstackV4UDP(t, [4]byte{8, 8, 8, 8}, 40000, 53, query)
	defer qpkt.DecRef()
	var qlist stack.PacketBufferList
	qlist.PushBack(qpkt)
	if _, err := ep.WritePackets(qlist); err != nil {
		t.Fatalf("query WritePackets: %v", err)
	}
	child.Drain()
	if f.pending.count.Load() != 1 {
		t.Fatalf("expected 1 pending query, got %d", f.pending.count.Load())
	}

	// 2. Inbound response resolving the name to learnedIP.
	resp := buildResponse(t, 0xABCD, "docs.github.com.", []dnsmessage.Resource{
		aResource(t, "docs.github.com.", learnedIP),
	})
	rpkt := inboundV4UDP(t, [4]byte{8, 8, 8, 8}, [4]byte{192, 168, 1, 2}, 53, 40000, resp)
	ep.DeliverNetworkPacket(header.IPv4ProtocolNumber, rpkt)
	rpkt.DecRef()

	if !f.learned.contains(tcpip.AddrFrom4(learnedIP)) {
		t.Fatal("address was not learned from the DNS response")
	}

	// 3. Egress to the learned address is now allowed.
	epkt := ethV4(t, learnedIP, 6, nil)
	defer epkt.DecRef()
	if got := f.evaluate(epkt).v; got != verdictAllow {
		t.Errorf("egress to learned IP: evaluate = %v, want allow", got)
	}
}

// TestLearnSpoofRejected verifies that a response with a mismatched transaction
// ID does not cause learning.
func TestLearnSpoofRejected(t *testing.T) {
	clock := faketime.NewManualClock()
	f := newTestFilter(t, Config{Domains: []string{"docs.github.com"}, IPs: []string{"8.8.8.8"}, Clock: clock})
	child := channel.New(16, 1500, "")
	defer child.Close()
	ep := New(child, f)

	query := buildQuery(t, 0x1111, "docs.github.com.", dnsmessage.TypeA)
	qpkt := netstackV4UDP(t, [4]byte{8, 8, 8, 8}, 40000, 53, query)
	defer qpkt.DecRef()
	var qlist stack.PacketBufferList
	qlist.PushBack(qpkt)
	ep.WritePackets(qlist)
	child.Drain()

	// Response with the WRONG transaction ID.
	resp := buildResponse(t, 0x2222, "docs.github.com.", []dnsmessage.Resource{
		aResource(t, "docs.github.com.", [4]byte{6, 6, 6, 6}),
	})
	rpkt := inboundV4UDP(t, [4]byte{8, 8, 8, 8}, [4]byte{192, 168, 1, 2}, 53, 40000, resp)
	ep.DeliverNetworkPacket(header.IPv4ProtocolNumber, rpkt)
	rpkt.DecRef()

	if f.learned.contains(tcpip.AddrFrom4([4]byte{6, 6, 6, 6})) {
		t.Error("learned an address from a spoofed (wrong-txID) response")
	}
}

// TestLearnSpoofWrongServerOrPort checks the other two pinned tuple fields: a
// response with the correct txID and question but from the wrong server address,
// or to the wrong client port, does not match the pending query and is not
// learned.
func TestLearnSpoofWrongServerOrPort(t *testing.T) {
	badIP := tcpip.AddrFrom4([4]byte{6, 6, 6, 6})
	for _, tc := range []struct {
		name        string
		respSrc     [4]byte
		respDstPort uint16
	}{
		{"wrong server address", [4]byte{9, 9, 9, 9}, 40000},
		{"wrong client port", [4]byte{8, 8, 8, 8}, 41000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			f := newTestFilter(t, Config{Domains: []string{"docs.github.com"}, IPs: []string{"8.8.8.8"}, Clock: clock})
			child := channel.New(16, 1500, "")
			defer child.Close()
			ep := New(child, f)

			query := buildQuery(t, 0x1111, "docs.github.com.", dnsmessage.TypeA)
			qpkt := netstackV4UDP(t, [4]byte{8, 8, 8, 8}, 40000, 53, query)
			defer qpkt.DecRef()
			var qlist stack.PacketBufferList
			qlist.PushBack(qpkt)
			ep.WritePackets(qlist)
			child.Drain()

			resp := buildResponse(t, 0x1111, "docs.github.com.", []dnsmessage.Resource{
				aResource(t, "docs.github.com.", [4]byte{6, 6, 6, 6}),
			})
			rpkt := inboundV4UDP(t, tc.respSrc, [4]byte{192, 168, 1, 2}, 53, tc.respDstPort, resp)
			ep.DeliverNetworkPacket(header.IPv4ProtocolNumber, rpkt)
			rpkt.DecRef()

			if f.learned.contains(badIP) {
				t.Errorf("learned an address from a response with the %s", tc.name)
			}
		})
	}
}

// --- DNS query handling ---

// captureDispatcher records packets delivered up the stack, flattened so no
// references are retained.
type captureDispatcher struct {
	protos []tcpip.NetworkProtocolNumber
	raws   [][]byte
}

func (d *captureDispatcher) DeliverNetworkPacket(proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	buf := pkt.ToBuffer()
	d.raws = append(d.raws, buf.Flatten())
	buf.Release()
	d.protos = append(d.protos, proto)
}

func (d *captureDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

// TestDNSQueryForwarding verifies that queries to an allowed resolver are
// always forwarded, never answered by the filter, and that only A/AAAA queries
// for allowlisted names are tracked for learning. In particular, a query for a
// name outside the domain allowlist must still resolve: its addresses may fall
// within the static IP allowlist.
func TestDNSQueryForwarding(t *testing.T) {
	cases := []struct {
		name    string
		domains []string
		qname   string
		qtype   dnsmessage.Type
		tracked bool
	}{
		{"no domain allowlist", nil, "docs.github.com.", dnsmessage.TypeA, false},
		{"non-address query type", []string{"docs.github.com"}, "docs.github.com.", dnsmessage.TypeMX, false},
		{"name outside the allowlist", []string{"docs.github.com"}, "blocked.example.com.", dnsmessage.TypeA, false},
		{"allowlisted name", []string{"docs.github.com"}, "docs.github.com.", dnsmessage.TypeA, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newTestFilter(t, Config{Domains: c.domains, IPs: []string{"8.8.8.8"}})
			child := channel.New(16, 1500, "")
			defer child.Close()
			ep := New(child, f)
			d := &captureDispatcher{}
			ep.Attach(d)

			query := buildQuery(t, 1, c.qname, c.qtype)
			qpkt := netstackV4UDP(t, [4]byte{8, 8, 8, 8}, 40000, 53, query)
			defer qpkt.DecRef()
			var list stack.PacketBufferList
			list.PushBack(qpkt)
			if _, err := ep.WritePackets(list); err != nil {
				t.Fatalf("WritePackets: %v", err)
			}
			if got := child.NumQueued(); got != 1 {
				t.Errorf("child queued %d packets, want 1 (query must be forwarded)", got)
			}
			child.Drain()
			if len(d.raws) != 0 {
				t.Errorf("dispatcher got %d packets, want 0", len(d.raws))
			}
			wantPending := int64(0)
			if c.tracked {
				wantPending = 1
			}
			if got := f.pending.count.Load(); got != wantPending {
				t.Errorf("pending count = %d, want %d", got, wantPending)
			}
		})
	}
}

// TestBlockedNameResolvingToStaticIP drives the full flow for a name outside
// the domain allowlist whose address lies inside a statically allowed CIDR:
// the query is forwarded, the response is not learned from (even with the
// snoop gate held open by a concurrent tracked query), and egress to the
// resolved address succeeds via the static allowlist alone.
func TestBlockedNameResolvingToStaticIP(t *testing.T) {
	f := newTestFilter(t, Config{
		Domains: []string{"docs.github.com"},
		IPs:     []string{"8.8.8.8", "10.0.0.0/8"},
	})
	child := channel.New(16, 1500, "")
	defer child.Close()
	ep := New(child, f)
	d := &captureDispatcher{}
	ep.Attach(d)

	resolver := [4]byte{8, 8, 8, 8}
	staticIP := [4]byte{10, 3, 7, 9}

	// An allowlisted query on another port keeps the inbound snoop gate open,
	// so the blocked name's response below is actually parsed and rejected
	// rather than skipped because nothing is pending.
	tracked := buildQuery(t, 0x1111, "docs.github.com.", dnsmessage.TypeA)
	tpkt := netstackV4UDP(t, resolver, 41000, 53, tracked)
	defer tpkt.DecRef()
	var tlist stack.PacketBufferList
	tlist.PushBack(tpkt)
	if _, err := ep.WritePackets(tlist); err != nil {
		t.Fatalf("tracked query WritePackets: %v", err)
	}

	// The blocked-name query is forwarded, unanswered, and untracked.
	query := buildQuery(t, 0x7777, "db.internal.corp.", dnsmessage.TypeA)
	qpkt := netstackV4UDP(t, resolver, 40000, 53, query)
	defer qpkt.DecRef()
	var qlist stack.PacketBufferList
	qlist.PushBack(qpkt)
	if _, err := ep.WritePackets(qlist); err != nil {
		t.Fatalf("WritePackets: %v", err)
	}
	if got := child.NumQueued(); got != 2 {
		t.Fatalf("child queued %d packets, want 2 (both queries forwarded)", got)
	}
	child.Drain()
	if len(d.raws) != 0 {
		t.Fatalf("dispatcher got %d packets, want 0 (no synthesized answer)", len(d.raws))
	}
	if got := f.pending.count.Load(); got != 1 {
		t.Fatalf("pending count = %d, want 1 (only the allowlisted query tracked)", got)
	}

	// The response resolves the blocked name into the allowed CIDR. It must
	// not grow the learned set: only tracked queries may grant learning.
	resp := buildResponse(t, 0x7777, "db.internal.corp.", []dnsmessage.Resource{
		aResource(t, "db.internal.corp.", staticIP),
	})
	rpkt := inboundV4UDP(t, resolver, [4]byte{192, 168, 1, 2}, 53, 40000, resp)
	ep.DeliverNetworkPacket(header.IPv4ProtocolNumber, rpkt)
	rpkt.DecRef()
	if f.learned.contains(tcpip.AddrFrom4(staticIP)) {
		t.Error("response for a non-allowlisted name was learned")
	}
	if got := f.pending.count.Load(); got != 1 {
		t.Errorf("pending count = %d, want 1 (unrelated response must not consume the tracked entry)", got)
	}

	// Egress to the resolved address is allowed, via the static CIDR alone.
	epkt := ethV4(t, staticIP, 6, nil)
	defer epkt.DecRef()
	if got := f.evaluate(epkt).v; got != verdictAllow {
		t.Errorf("egress to statically allowed resolved IP: evaluate = %v, want allow", got)
	}

	// A destination outside both lists stays blocked, so the pass above is
	// attributable to the static CIDR, not an accidentally open filter.
	bpkt := ethV4(t, [4]byte{11, 1, 1, 1}, 6, nil)
	defer bpkt.DecRef()
	if got := f.evaluate(bpkt).v; got != verdictDropNotAllowed {
		t.Errorf("egress outside allowlists: evaluate = %v, want drop", got)
	}
}

// --- helpers ---

func mustAddr(t *testing.T, s string) tcpip.Address {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return netipToAddr(a)
}

// ethFrame builds a PacketBuffer for a frame with the given EtherType and L3
// payload. If consumeLink, the ethernet header is consumed into the link-header
// slot (packet-socket / inbound shape), leaving NetworkHeader empty.
func ethFrame(t *testing.T, etherType uint16, l3 []byte, consumeLink bool) *stack.PacketBuffer {
	t.Helper()
	eth := make([]byte, header.EthernetMinimumSize)
	binary.BigEndian.PutUint16(eth[12:14], etherType)
	frame := append(eth, l3...)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
	if consumeLink {
		if _, ok := pkt.LinkHeader().Consume(header.EthernetMinimumSize); !ok {
			t.Fatal("failed to consume link header")
		}
	}
	return pkt
}

// buildV4 builds an IPv4 header + payload with the given destination and
// protocol.
func buildV4(dst [4]byte, proto uint8, opts, payload []byte) []byte {
	ihl := header.IPv4MinimumSize + len(opts)
	b := make([]byte, ihl+len(payload))
	b[0] = (4 << 4) | uint8(ihl/4)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b))) // total length
	b[9] = proto
	copy(b[16:20], dst[:])
	copy(b[header.IPv4MinimumSize:ihl], opts)
	copy(b[ihl:], payload)
	return b
}

func buildV6(dst tcpip.Address, nextHeader uint8, payload []byte) []byte {
	b := make([]byte, header.IPv6MinimumSize+len(payload))
	b[0] = 6 << 4
	binary.BigEndian.PutUint16(b[4:6], uint16(len(payload)))
	b[6] = nextHeader
	d := dst.As16()
	copy(b[24:40], d[:])
	copy(b[header.IPv6MinimumSize:], payload)
	return b
}

// ethV4 builds an ethernet+IPv4 packet in packet-socket shape (link consumed,
// L3 in Data).
func ethV4(t *testing.T, dst [4]byte, proto uint8, payload []byte) *stack.PacketBuffer {
	return ethFrame(t, 0x0800, buildV4(dst, proto, nil, payload), true)
}

func ethV4WithOptions(t *testing.T, dst [4]byte, opts []byte) *stack.PacketBuffer {
	return ethFrame(t, 0x0800, buildV4(dst, 6, opts, nil), true)
}

func ethV6(t *testing.T, dst tcpip.Address, nextHeader uint8, payload []byte) *stack.PacketBuffer {
	return ethFrame(t, 0x86dd, buildV6(dst, nextHeader, payload), true)
}

// ethV4ICMPEcho builds an IPv4 ICMP echo request to dst.
func ethV4ICMPEcho(t *testing.T, dst [4]byte) *stack.PacketBuffer {
	icmp := make([]byte, header.ICMPv4MinimumSize)
	header.ICMPv4(icmp).SetType(header.ICMPv4Echo)
	return ethV4(t, dst, uint8(header.ICMPv4ProtocolNumber), icmp)
}

// ethV6WithRouting builds an IPv6 frame carrying a minimal Routing extension
// header (next header TCP), used to check that the filter drops it.
func ethV6WithRouting(t *testing.T, dst tcpip.Address) *stack.PacketBuffer {
	routing := uint8(header.IPv6RoutingExtHdrIdentifier)
	rh := []byte{uint8(header.TCPProtocolNumber), 0, 0, 0, 0, 0, 0, 0}
	return ethFrame(t, 0x86dd, buildV6(dst, routing, rh), true)
}

// ethV4Cooked builds a cooked-packet-socket-shaped IPv4 frame: L3 in Data,
// NetworkHeader empty, EtherType claims IPv4.
func ethV4Cooked(t *testing.T, dst [4]byte) *stack.PacketBuffer {
	return ethFrame(t, 0x0800, buildV4(dst, 6, nil, nil), true)
}

// arpEtherTypeCarryingIPv4 crafts a frame whose EtherType is ARP but whose
// payload is an IPv4 packet: it must be rejected as a malformed ARP.
func arpEtherTypeCarryingIPv4(t *testing.T, dst [4]byte) *stack.PacketBuffer {
	return ethFrame(t, 0x0806, buildV4(dst, 6, nil, nil), true)
}

// ethARP builds a minimal valid ARP frame, optionally oversized.
func ethARP(t *testing.T, oversized bool) *stack.PacketBuffer {
	arp := make([]byte, header.ARPSize)
	// Encode a syntactically valid ARP request: HW type 1 (eth), proto 0x0800,
	// HW addr len 6, proto addr len 4, op 1.
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], 0x0800)
	arp[4] = 6
	arp[5] = 4
	binary.BigEndian.PutUint16(arp[6:8], 1)
	l3 := arp
	if oversized {
		l3 = append(arp, make([]byte, 64)...)
	}
	return ethFrame(t, 0x0806, l3, true)
}

// netstackV4UDP builds an outbound netstack-origin IPv4/UDP packet: headers in
// their parsed slots, payload in Data, ethernet link header present.
func netstackV4UDP(t *testing.T, dst [4]byte, srcPort, dstPort uint16, payload []byte) *stack.PacketBuffer {
	t.Helper()
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.EthernetMinimumSize + header.IPv4MinimumSize + header.UDPMinimumSize,
		Payload:            buffer.MakeWithData(payload),
	})
	udp := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	udp.Encode(&header.UDPFields{SrcPort: srcPort, DstPort: dstPort, Length: uint16(header.UDPMinimumSize + len(payload))})
	ip := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize + header.UDPMinimumSize + len(payload)),
		Protocol:    uint8(header.UDPProtocolNumber),
		TTL:         64,
		SrcAddr:     tcpip.AddrFrom4([4]byte{192, 168, 1, 2}),
		DstAddr:     tcpip.AddrFrom4(dst),
	})
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	eth.Encode(&header.EthernetFields{Type: header.IPv4ProtocolNumber})
	return pkt
}

// inboundV4UDP builds an inbound IPv4/UDP packet as delivered to
// DeliverNetworkPacket: the link header has already been consumed, so the L3
// packet is at the front of Data.
func inboundV4UDP(t *testing.T, src, dst [4]byte, srcPort, dstPort uint16, payload []byte) *stack.PacketBuffer {
	t.Helper()
	udp := make([]byte, header.UDPMinimumSize)
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(header.UDPMinimumSize+len(payload)))
	ip := buildV4(dst, uint8(header.UDPProtocolNumber), nil, append(udp, payload...))
	copy(ip[12:16], src[:]) // set source address
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(ip)})
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	return pkt
}
