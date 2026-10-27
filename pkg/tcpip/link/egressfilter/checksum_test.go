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
	"bytes"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestDNSReceiveChecksumCapabilities(t *testing.T) {
	for _, netProto := range []tcpip.NetworkProtocolNumber{header.IPv4ProtocolNumber, header.IPv6ProtocolNumber} {
		name := "IPv4"
		if netProto == header.IPv6ProtocolNumber {
			name = "IPv6"
		}
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name         string
				offload      bool
				packetFlag   bool
				corruption   string
				wantLearning bool
			}{
				{name: "software validates", wantLearning: true},
				{name: "software rejects UDP checksum", corruption: "UDP checksum"},
				{name: "packet flag cannot bypass software validation", packetFlag: true, corruption: "UDP checksum"},
				{name: "offload before packet flag is set", offload: true, corruption: "UDP checksum", wantLearning: true},
				{name: "offload with packet flag set", offload: true, packetFlag: true, corruption: "UDP checksum", wantLearning: true},
				{name: "offload still rejects malformed UDP length", offload: true, corruption: "UDP length"},
				{name: "software rejects IPv4 header checksum", corruption: "IPv4 checksum"},
				{name: "packet flag cannot bypass IPv4 header validation", packetFlag: true, corruption: "IPv4 checksum"},
				{name: "offload skips IPv4 checksum like NIC", offload: true, corruption: "IPv4 checksum", wantLearning: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if netProto == header.IPv6ProtocolNumber && tc.corruption == "IPv4 checksum" {
						t.Skip("IPv6 has no header checksum")
					}
					server := tcpip.AddrFrom4([4]byte{8, 8, 8, 8})
					local := tcpip.AddrFrom4([4]byte{192, 168, 1, 2})
					if netProto == header.IPv6ProtocolNumber {
						server = mustAddr(t, "2001:db8::53")
						local = mustAddr(t, "2001:db8::1")
					}
					f := newTestFilter(t, Config{})
					now := f.clock.NowMonotonic()
					f.pending.track(pendingKey{server: server, local: local, clientPort: 40000, txID: 1}, "a.example.com", dnsmessage.TypeA, now, now.Add(queryTTL))
					response := buildResponse(t, 1, "a.example.com.", []dnsmessage.Resource{aResource(t, "a.example.com.", [4]byte{203, 0, 113, 1})})
					var pkt *stack.PacketBuffer
					udpOffset := header.IPv4MinimumSize
					if netProto == header.IPv4ProtocolNumber {
						pkt = inboundV4UDP(t, server.As4(), local.As4(), dnsPort, 40000, response)
					} else {
						pkt = inboundV6FragmentedUDP(t, server, local, dnsPort, 40000, response, false)
						udpOffset = header.IPv6MinimumSize + 8
					}
					defer pkt.DecRef()
					raw, ok := pkt.Data().PullUp(pkt.Data().Size())
					if !ok {
						t.Fatal("PullUp failed")
					}
					udp := header.UDP(raw[udpOffset:])
					switch tc.corruption {
					case "UDP checksum":
						badChecksum := udp.Checksum() ^ 1
						if badChecksum == 0 {
							badChecksum = 2
						}
						udp.SetChecksum(badChecksum)
					case "UDP length":
						udp.SetLength(header.UDPMinimumSize - 1)
					case "IPv4 checksum":
						raw[8] ^= 1
					}
					before := append([]byte(nil), raw...)
					pkt.RXChecksumValidated = tc.packetFlag
					child := channel.New(4, 1500, "")
					defer child.Close()
					if tc.offload {
						child.LinkEPCapabilities |= stack.CapabilityRXChecksumOffload
					}
					ep := New(child, f)
					d := &captureDispatcher{}
					ep.Attach(d)
					child.InjectInbound(netProto, pkt)
					if got := f.learned.contains(tcpip.AddrFrom4([4]byte{203, 0, 113, 1})); got != tc.wantLearning {
						t.Errorf("learned = %t, want %t", got, tc.wantLearning)
					}
					if pkt.RXChecksumValidated != tc.packetFlag {
						t.Error("snoop changed original packet checksum metadata")
					}
					if len(d.raws) != 1 || !bytes.Equal(d.raws[0], before) {
						t.Error("snoop changed or dropped original packet")
					}
				})
			}
		})
	}
}

func TestDNSReceiveChecksumOffload(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})
	defer s.Destroy()
	lower := channel.New(16, 1500, "")
	lower.LinkEPCapabilities |= stack.CapabilityRXChecksumOffload
	defer lower.Close()
	f := newTestFilter(t, Config{Domains: []string{"docs.example.com"}, IPs: []string{"8.8.8.8"}, Clock: s.Clock()})
	if err := s.CreateNIC(1, New(lower, f)); err != nil {
		t.Fatal(err)
	}
	local := tcpip.AddrFrom4([4]byte{192, 168, 1, 2})
	server := tcpip.AddrFrom4([4]byte{8, 8, 8, 8})
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: local.WithPrefix()}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close()
	if err := ep.Bind(tcpip.FullAddress{NIC: 1, Addr: local, Port: 40000}); err != nil {
		t.Fatal(err)
	}
	query := buildQuery(t, 1, "docs.example.com.", dnsmessage.TypeA)
	if _, err := ep.Write(bytes.NewReader(query), tcpip.WriteOptions{To: &tcpip.FullAddress{NIC: 1, Addr: server, Port: 53}}); err != nil {
		t.Fatal(err)
	}
	lower.Drain()
	if f.pending.count.Load() != 1 {
		t.Fatal("outbound DNS query was not tracked")
	}
	answer := [4]byte{203, 0, 113, 10}
	response := buildResponse(t, 1, "docs.example.com.", []dnsmessage.Resource{aResource(t, "docs.example.com.", answer)})
	pkt := inboundV4UDP(t, [4]byte{8, 8, 8, 8}, [4]byte{192, 168, 1, 2}, 53, 40000, response)
	defer pkt.DecRef()
	raw, ok := pkt.Data().PullUp(pkt.Data().Size())
	if !ok {
		t.Fatal("PullUp failed")
	}
	udpHeader := header.UDP(raw[header.IPv4MinimumSize:])
	udpHeader.SetChecksum(header.PseudoHeaderChecksum(header.UDPProtocolNumber, server, local, udpHeader.Length()))
	// The readv and XDP ingress paths set capability metadata only at the NIC.
	if pkt.RXChecksumValidated {
		t.Fatal("unexpected pre-set checksum metadata")
	}
	lower.InjectInbound(ipv4.ProtocolNumber, pkt)
	var received bytes.Buffer
	if _, err := ep.Read(&received, tcpip.ReadOptions{}); err != nil {
		t.Fatalf("receiving DNS response: %v", err)
	}
	if !bytes.Equal(received.Bytes(), response) {
		t.Fatal("wrong DNS payload delivered")
	}
	if !f.learned.contains(tcpip.AddrFrom4(answer)) {
		t.Fatal("DNS response reached the UDP endpoint without learning the answer address")
	}
}
