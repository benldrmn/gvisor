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

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// workloadV4 is the source address the netstack-origin TCP builders use for the
// sandboxed workload, matching the UDP builders in egressfilter_test.go.
var workloadV4 = tcpip.AddrFrom4([4]byte{192, 168, 1, 2})

// netstackV4TCP builds an outbound netstack-origin IPv4/TCP segment: headers in
// their parsed slots (so synthesizeRST can read the transport header), no
// payload, ethernet link header present.
func netstackV4TCP(t *testing.T, dst [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags header.TCPFlags) *stack.PacketBuffer {
	t.Helper()
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.EthernetMinimumSize + header.IPv4MinimumSize + header.TCPMinimumSize,
	})
	tcp := header.TCP(pkt.TransportHeader().Push(header.TCPMinimumSize))
	tcp.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seq,
		AckNum:     ack,
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
		WindowSize: 65535,
	})
	ip := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize + header.TCPMinimumSize),
		Protocol:    uint8(header.TCPProtocolNumber),
		TTL:         64,
		SrcAddr:     workloadV4,
		DstAddr:     tcpip.AddrFrom4(dst),
	})
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	eth.Encode(&header.EthernetFields{Type: header.IPv4ProtocolNumber})
	return pkt
}

// netstackV6TCP is the IPv6 counterpart of netstackV4TCP.
func netstackV6TCP(t *testing.T, dst tcpip.Address, srcPort, dstPort uint16, seq, ack uint32, flags header.TCPFlags) *stack.PacketBuffer {
	t.Helper()
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.EthernetMinimumSize + header.IPv6MinimumSize + header.TCPMinimumSize,
	})
	tcp := header.TCP(pkt.TransportHeader().Push(header.TCPMinimumSize))
	tcp.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seq,
		AckNum:     ack,
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
		WindowSize: 65535,
	})
	ip := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     header.TCPMinimumSize,
		TransportProtocol: header.TCPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           mustAddr(t, "2001:db8::2"),
		DstAddr:           dst,
	})
	pkt.NetworkProtocolNumber = header.IPv6ProtocolNumber
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	eth.Encode(&header.EthernetFields{Type: header.IPv6ProtocolNumber})
	return pkt
}

// writeOne runs a single packet through the endpoint and returns the endpoint's
// capture dispatcher and lower channel for assertions.
func writeOne(t *testing.T, f *Filter, pkt *stack.PacketBuffer) (*captureDispatcher, *channel.Endpoint) {
	t.Helper()
	child := channel.New(16, 1500, "")
	t.Cleanup(child.Close)
	ep := New(child, f)
	d := &captureDispatcher{}
	ep.Attach(d)
	var list stack.PacketBufferList
	list.PushBack(pkt)
	if _, err := ep.WritePackets(list); err != nil {
		t.Fatalf("WritePackets: %v", err)
	}
	return d, child
}

// TestBlockedTCPSynResetV4 verifies a SYN to a non-allowlisted destination is
// dropped and answered with a well-formed RST+ACK (swapped addresses/ports,
// seq 0, ack = SYN seq + 1, valid checksums) delivered back up the stack.
func TestBlockedTCPSynResetV4(t *testing.T) {
	f := newTestFilter(t, Config{IPs: []string{"9.9.9.9"}})
	const clientPort, serverPort = 44000, 443
	const clientISS = 0x11223344
	syn := netstackV4TCP(t, [4]byte{1, 2, 3, 4}, clientPort, serverPort, clientISS, 0, header.TCPFlagSyn)
	defer syn.DecRef()

	d, child := writeOne(t, f, syn)
	if got := child.NumQueued(); got != 0 {
		t.Errorf("child queued %d packets, want 0 (blocked SYN must not egress)", got)
	}
	if len(d.raws) != 1 {
		t.Fatalf("dispatcher got %d packets, want 1 synthesized RST", len(d.raws))
	}
	if d.protos[0] != header.IPv4ProtocolNumber {
		t.Errorf("delivered protocol = %d, want IPv4", d.protos[0])
	}
	raw := d.raws[0]
	ip := header.IPv4(raw)
	if !ip.IsChecksumValid() {
		t.Error("synthesized IPv4 checksum is invalid")
	}
	if got, want := ip.SourceAddress(), tcpip.AddrFrom4([4]byte{1, 2, 3, 4}); got != want {
		t.Errorf("RST src = %s, want %s (the blocked peer)", got, want)
	}
	if got, want := ip.DestinationAddress(), workloadV4; got != want {
		t.Errorf("RST dst = %s, want %s (the workload)", got, want)
	}
	if ip.Protocol() != uint8(header.TCPProtocolNumber) {
		t.Fatalf("RST protocol = %d, want TCP", ip.Protocol())
	}
	tcp := header.TCP(raw[header.IPv4MinimumSize:])
	if got, want := tcp.SourcePort(), uint16(serverPort); got != want {
		t.Errorf("RST src port = %d, want %d", got, want)
	}
	if got, want := tcp.DestinationPort(), uint16(clientPort); got != want {
		t.Errorf("RST dst port = %d, want %d", got, want)
	}
	if got, want := tcp.Flags(), header.TCPFlagRst|header.TCPFlagAck; got != want {
		t.Errorf("RST flags = %v, want RST|ACK", got)
	}
	if got := tcp.SequenceNumber(); got != 0 {
		t.Errorf("RST seq = %d, want 0 (SYN had no ACK)", got)
	}
	if got, want := tcp.AckNumber(), uint32(clientISS+1); got != want {
		t.Errorf("RST ack = %#x, want %#x (SYN seq + 1)", got, want)
	}
	if !tcp.IsChecksumValid(ip.SourceAddress(), ip.DestinationAddress(), 0, 0) {
		t.Error("synthesized TCP checksum is invalid")
	}
}

// TestBlockedTCPSynResetV6 is the IPv6 analogue of TestBlockedTCPSynResetV4.
func TestBlockedTCPSynResetV6(t *testing.T) {
	f := newTestFilter(t, Config{IPs: []string{"2001:4860::/32"}})
	const clientPort, serverPort = 45000, 443
	const clientISS = 0x55667788
	dst := mustAddr(t, "2606:4700::1") // not in 2001:4860::/32
	syn := netstackV6TCP(t, dst, clientPort, serverPort, clientISS, 0, header.TCPFlagSyn)
	defer syn.DecRef()

	d, child := writeOne(t, f, syn)
	if got := child.NumQueued(); got != 0 {
		t.Errorf("child queued %d packets, want 0", got)
	}
	if len(d.raws) != 1 {
		t.Fatalf("dispatcher got %d packets, want 1 synthesized RST", len(d.raws))
	}
	if d.protos[0] != header.IPv6ProtocolNumber {
		t.Errorf("delivered protocol = %d, want IPv6", d.protos[0])
	}
	raw := d.raws[0]
	ip := header.IPv6(raw)
	if got := ip.SourceAddress(); got != dst {
		t.Errorf("RST src = %s, want %s (the blocked peer)", got, dst)
	}
	if got, want := ip.DestinationAddress(), mustAddr(t, "2001:db8::2"); got != want {
		t.Errorf("RST dst = %s, want %s (the workload)", got, want)
	}
	tcp := header.TCP(raw[header.IPv6MinimumSize:])
	if got, want := tcp.Flags(), header.TCPFlagRst|header.TCPFlagAck; got != want {
		t.Errorf("RST flags = %v, want RST|ACK", got)
	}
	if got, want := tcp.AckNumber(), uint32(clientISS+1); got != want {
		t.Errorf("RST ack = %#x, want %#x", got, want)
	}
	if !tcp.IsChecksumValid(ip.SourceAddress(), ip.DestinationAddress(), 0, 0) {
		t.Error("synthesized TCP checksum is invalid")
	}
}

// TestBlockedTCPAckSegmentUsesAckNum verifies the RFC 9293 reset rule for a
// segment that already carries an ACK: the RST takes its sequence number from
// the segment's ACK field and carries no ACK of its own.
func TestBlockedTCPAckSegmentUsesAckNum(t *testing.T) {
	f := newTestFilter(t, Config{IPs: []string{"9.9.9.9"}})
	const segAck = 0xDEADBEEF
	seg := netstackV4TCP(t, [4]byte{1, 2, 3, 4}, 44000, 443, 0x1000, segAck, header.TCPFlagAck)
	defer seg.DecRef()

	d, _ := writeOne(t, f, seg)
	if len(d.raws) != 1 {
		t.Fatalf("dispatcher got %d packets, want 1 RST", len(d.raws))
	}
	tcp := header.TCP(d.raws[0][header.IPv4MinimumSize:])
	if got, want := tcp.Flags(), header.TCPFlagRst; got != want {
		t.Errorf("RST flags = %v, want RST only (incoming segment had ACK)", got)
	}
	if got := tcp.SequenceNumber(); got != uint32(segAck) {
		t.Errorf("RST seq = %#x, want %#x (incoming ACK number)", got, uint32(segAck))
	}
	if got := tcp.AckNumber(); got != 0 {
		t.Errorf("RST ack = %d, want 0", got)
	}
}

// TestIncomingRSTNotReflected verifies a blocked segment that is itself a RST is
// dropped silently: answering a reset with a reset would create a RST storm.
func TestIncomingRSTNotReflected(t *testing.T) {
	f := newTestFilter(t, Config{IPs: []string{"9.9.9.9"}})
	seg := netstackV4TCP(t, [4]byte{1, 2, 3, 4}, 44000, 443, 5, 6, header.TCPFlagRst|header.TCPFlagAck)
	defer seg.DecRef()

	d, child := writeOne(t, f, seg)
	if len(d.raws) != 0 {
		t.Errorf("dispatcher got %d packets, want 0 (never answer a RST with a RST)", len(d.raws))
	}
	if got := child.NumQueued(); got != 0 {
		t.Errorf("child queued %d, want 0 (blocked RST is still dropped)", got)
	}
}

// TestBlockedUDPNotReset verifies non-TCP drops are not reset.
func TestBlockedUDPNotReset(t *testing.T) {
	f := newTestFilter(t, Config{IPs: []string{"9.9.9.9"}})
	pkt := netstackV4UDP(t, [4]byte{1, 2, 3, 4}, 40000, 5000, []byte("hello"))
	defer pkt.DecRef()

	d, _ := writeOne(t, f, pkt)
	if len(d.raws) != 0 {
		t.Errorf("dispatcher got %d packets, want 0 (no RST for non-TCP)", len(d.raws))
	}
}

// TestPacketSocketTCPNotReset verifies a packet-socket-origin TCP segment (no
// parsed transport header) is dropped without a RST: reset synthesis is scoped
// to netstack-origin traffic.
func TestPacketSocketTCPNotReset(t *testing.T) {
	f := newTestFilter(t, Config{IPs: []string{"9.9.9.9"}})
	tcpHdr := make([]byte, header.TCPMinimumSize)
	header.TCP(tcpHdr).Encode(&header.TCPFields{
		SrcPort:    44000,
		DstPort:    443,
		SeqNum:     7,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
	})
	pkt := ethV4(t, [4]byte{1, 2, 3, 4}, uint8(header.TCPProtocolNumber), tcpHdr)
	defer pkt.DecRef()

	d, child := writeOne(t, f, pkt)
	if len(d.raws) != 0 {
		t.Errorf("dispatcher got %d packets, want 0 (packet-socket TCP is not reset)", len(d.raws))
	}
	if got := child.NumQueued(); got != 0 {
		t.Errorf("child queued %d, want 0 (blocked raw SYN is still dropped)", got)
	}
}
