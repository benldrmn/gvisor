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
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type benchmarkDispatcher struct{}

func (*benchmarkDispatcher) DeliverNetworkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}
func (*benchmarkDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer)    {}

func BenchmarkPacketPath(b *testing.B) {
	defer refs.SetLeakMode(refs.GetLeakMode())
	refs.SetLeakMode(refs.NoLeakChecking)

	for _, path := range []string{"EgressExact", "EgressCIDR", "EgressLearned", "IngressIdle", "IngressPendingDNS"} {
		b.Run(path, func(b *testing.B) {
			for _, enabled := range []bool{false, true} {
				name := "Filter=off"
				if enabled {
					name = "Filter=on"
				}
				b.Run(name, func(b *testing.B) {
					clock := faketime.NewManualClock()
					cfg := Config{Clock: clock, Domains: []string{"example.com"}}
					switch path {
					case "EgressExact":
						cfg.IPs = []string{"192.0.2.1"}
					case "EgressCIDR":
						cfg.IPs = []string{"192.0.2.0/24"}
					}
					f, err := NewFilter(cfg)
					if err != nil {
						b.Fatal(err)
					}
					if path == "EgressLearned" {
						f.learned.addBatch([]tcpip.Address{tcpip.AddrFrom4([4]byte{192, 0, 2, 1})})
					}
					if path == "IngressPendingDNS" {
						now := clock.NowMonotonic()
						f.pending.track(pendingKey{}, "example.com", dnsmessage.TypeA, now, now.Add(queryTTL))
					}
					lower := channel.New(1, 1500, "")
					defer lower.Close()
					var ep stack.LinkEndpoint = lower
					if enabled {
						ep = New(lower, f)
					}
					ep.Attach(&benchmarkDispatcher{})

					raw := buildV4([4]byte{192, 0, 2, 1}, uint8(header.TCPProtocolNumber), nil, make([]byte, 1480))
					ip := header.IPv4(raw)
					ip.SetTTL(64)
					ip.SetChecksum(^ip.CalculateChecksum())
					pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
						ReserveHeaderBytes: header.EthernetMinimumSize,
						Payload:            buffer.MakeWithData(raw),
					})
					defer pkt.DecRef()
					pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
					eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
					eth.Encode(&header.EthernetFields{Type: header.IPv4ProtocolNumber})
					inbound := path == "IngressIdle" || path == "IngressPendingDNS"
					if !inbound {
						pkt.NetworkHeader().Consume(header.IPv4MinimumSize)
						pkt.TransportHeader().Consume(header.TCPMinimumSize)
					}
					var packets stack.PacketBufferList
					packets.PushBack(pkt)
					b.ReportAllocs()
					b.SetBytes(int64(len(raw)))
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if inbound {
							lower.InjectInbound(header.IPv4ProtocolNumber, pkt)
						} else {
							if n, err := ep.WritePackets(packets); n != 1 || err != nil {
								b.Fatalf("WritePackets = (%d, %v), want (1, nil)", n, err)
							}
							lower.Read().DecRef()
						}
					}
				})
			}
		})
	}
}
