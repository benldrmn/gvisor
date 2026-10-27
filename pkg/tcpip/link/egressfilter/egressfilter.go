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

// Package egressfilter enforces a destination-IP allowlist at the link layer,
// including raw and packet-socket traffic. It learns addresses for allowed
// domains from UDP DNS responses.
package egressfilter

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Endpoint is a stack.LinkEndpoint that filters egress and snoops DNS.
//
// +stateify savable
type Endpoint struct {
	nested.Endpoint
	// filter is shared by all external NICs and rebuilt on restore.
	// Learned addresses are not saved.
	filter *Filter `state:"nosave"`
}

var _ stack.LinkEndpoint = (*Endpoint)(nil)
var _ stack.NetworkDispatcher = (*Endpoint)(nil)
var _ stack.GSOEndpoint = (*Endpoint)(nil)

// New wraps lower with f. The filter may be shared across NICs.
func New(lower stack.LinkEndpoint, f *Filter) *Endpoint {
	e := &Endpoint{filter: f}
	e.Endpoint.Init(lower, e)
	return e
}

// process filters pkt and tracks allowed DNS queries. It reports whether to
// forward pkt.
func (e *Endpoint) process(pkt *stack.PacketBuffer) bool {
	f := e.filter
	res := f.evaluate(pkt)
	if res.v != verdictAllow {
		logDrop(res)
		// Reset blocked TCP connections so connect returns ECONNREFUSED.
		if res.v == verdictDropNotAllowed {
			if resp, respProto := synthesizeRST(pkt, res.l4proto); resp != nil {
				// Bypass this endpoint's inbound DNS snooping.
				e.Endpoint.DeliverNetworkPacket(respProto, resp)
				resp.DecRef()
			}
		}
		return false
	}
	f.trackDNSQuery(pkt, res.dst, res.l4proto)
	return true
}

// WritePackets implements stack.LinkEndpoint.
func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	slice := pkts.AsSlice()

	// Avoid allocating a new list when no packets are dropped.
	firstDrop := -1
	for i, pkt := range slice {
		if !e.process(pkt) {
			firstDrop = i
			break
		}
	}
	if firstDrop < 0 {
		return e.Endpoint.WritePackets(pkts)
	}

	// The caller retains all packet references. origIdx maps short writes back
	// to the original list, including dropped packets.
	var allowed stack.PacketBufferList
	var origIdx []int
	for i, pkt := range slice[:firstDrop] {
		allowed.PushBack(pkt)
		origIdx = append(origIdx, i)
	}
	for i := firstDrop + 1; i < len(slice); i++ {
		if e.process(slice[i]) {
			allowed.PushBack(slice[i])
			origIdx = append(origIdx, i)
		}
	}
	if allowed.Len() > 0 {
		if n, err := e.Endpoint.WritePackets(allowed); err != nil {
			// Count written and dropped packets before the first unwritten packet.
			return origIdx[n], err
		}
	}
	// Count policy drops as sent to avoid reporting a link error.
	return pkts.Len(), nil
}

// DeliverNetworkPacket implements stack.NetworkDispatcher. Learn DNS answers
// before delivery so the workload can connect as soon as resolution completes.
func (e *Endpoint) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	f := e.filter
	if f.pending.nonEmpty() {
		// Expire unanswered queries so idle traffic stops triggering DNS parsing.
		f.pending.maybeSweep(f.clock.NowMonotonic())
		if f.pending.nonEmpty() {
			// The NIC sets RXChecksumValidated after this callback. Derive it from
			// link capabilities here too.
			rxChecksumValidated := e.Capabilities()&stack.CapabilityRXChecksumOffload != 0
			f.snoopInbound(protocol, pkt, rxChecksumValidated)
		}
	}
	e.Endpoint.DeliverNetworkPacket(protocol, pkt)
}
