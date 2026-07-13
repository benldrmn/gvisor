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

// Package egressfilter provides a link-endpoint wrapper that enforces a
// destination-IP egress allowlist and grows it by snooping plain UDP DNS
// responses for a configured set of domains. It sits in the Sentry's link
// chain, so it sees every outbound packet, including raw and packet-socket
// traffic that bypasses the transport layer, and is not reachable by any
// in-sandbox syscall. Encrypted DNS and DNS-over-TCP are not snooped, so
// addresses they resolve are never learned. See the networking user guide for
// the full model.
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
	// filter is shared across every wrapped NIC and reconstructed on restore, so
	// it is not saved. Learned state is lost on restore by design.
	filter *Filter `state:"nosave"`
}

var _ stack.LinkEndpoint = (*Endpoint)(nil)
var _ stack.NetworkDispatcher = (*Endpoint)(nil)
var _ stack.GSOEndpoint = (*Endpoint)(nil)

// New wraps lower so that every egress packet is checked against f and DNS is
// snooped in both directions. f is internally synchronized and may be shared
// across multiple NIC endpoints.
func New(lower stack.LinkEndpoint, f *Filter) *Endpoint {
	e := &Endpoint{filter: f}
	e.Endpoint.Init(lower, e)
	return e
}

// process evaluates one outbound packet, tracking DNS queries as needed, and
// reports whether pkt should be forwarded to the lower endpoint.
func (e *Endpoint) process(pkt *stack.PacketBuffer) bool {
	f := e.filter
	res := f.evaluate(pkt)
	if res.v != verdictAllow {
		logDrop(res)
		// A blocked TCP segment is answered with a RST so the workload's
		// connect() fails fast instead of hanging on SYN retransmits.
		// Malformed and protocol-policy drops stay silent (see synthesizeRST).
		if res.v == verdictDropNotAllowed {
			if resp, respProto := synthesizeRST(pkt, res.l4proto); resp != nil {
				// Deliver directly to the upper dispatcher (as loopback does),
				// bypassing this endpoint's own inbound snoop.
				e.Endpoint.DeliverNetworkPacket(respProto, resp)
				resp.DecRef()
			}
		}
		return false
	}
	f.trackDNSQuery(pkt, res.dst, res.l4proto)
	return true
}

// WritePackets implements stack.LinkEndpoint. It forwards only the packets
// that pass the egress policy. Disallowed packets are dropped with a
// rate-limited log, except that a TCP segment to a blocked destination is
// answered with a RST (see process).
func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	slice := pkts.AsSlice()

	// In the common case nothing is dropped and the original list is
	// forwarded untouched, with no allocation.
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

	// Rebuild the list without the dropped packets. PushBack does not take a
	// reference, so the caller still owns and releases every buffer. origIdx maps
	// each kept packet to its position in the original list, so a short write from
	// the lower endpoint is reported as a count into that list.
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
			// The lower endpoint wrote n kept packets before failing. Everything
			// before the first unwritten kept packet in the original list was
			// written or deliberately dropped, so report that many as handled.
			return origIdx[n], err
		}
	}
	// Dropped packets count as sent: a policy drop is deliberate, and a short
	// count would make the caller treat it as a link error.
	return pkts.Len(), nil
}

// DeliverNetworkPacket implements stack.NetworkDispatcher. Inbound packets are
// never filtered (the policy is egress-only), but DNS responses are snooped to
// grow the learned-IP set. Learning happens before delivery so the workload's
// resolve-then-connect sequence cannot race the learner.
func (e *Endpoint) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	f := e.filter
	if f.pending.nonEmpty() {
		// Reclaim expired queries (throttled) so a query that never gets a
		// response does not keep the gate open and tax every inbound packet.
		f.pending.maybeSweep(f.clock.NowMonotonic())
		if f.pending.nonEmpty() {
			f.snoopInbound(protocol, pkt)
		}
	}
	e.Endpoint.DeliverNetworkPacket(protocol, pkt)
}
