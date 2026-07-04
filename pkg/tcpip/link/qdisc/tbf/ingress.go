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

package tbf

import (
	"time"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// ingressDropLogger rate-limits the warning logged when inbound packets are
// dropped because the shaper's backlog is full. Unlike egress drops, which
// surface to the NIC as ErrNoBufferSpace, ingress drops have no error path
// back into the stack, so this log line and the dropped counter are the only
// signals that the backlog is overflowing.
var ingressDropLogger = log.BasicRateLimitedLogger(time.Minute)

// Ingress is a stack.LinkEndpoint decorator that applies single-rate token
// bucket shaping to inbound traffic before it is delivered to the network
// stack. Unlike Linux, where the ingress hook can only police (drop), gVisor
// owns the receive path in userspace and can queue inbound packets until the
// bucket refills, mirroring the egress TBF's behavior. Packets that arrive
// while the backlog queue is full are dropped. All inbound traffic on the
// link is shaped, including ARP and NDP, and delivery into the stack is
// serialized on the shaper's single dispatch goroutine.
//
// Outbound traffic passes through unmodified; pair with the egress TBF qdisc
// to shape both directions. Packets delivered directly to packet endpoints
// via DeliverLinkPacket are not shaped, but no link endpoint used with this
// wrapper calls it: runsc NICs deliver to packet endpoints from within the
// NIC's (post-shaper) DeliverNetworkPacket.
//
// +stateify savable
type Ingress struct {
	nested.Endpoint

	// dropped counts inbound packets dropped because the backlog queue was
	// full. Packets discarded by Close or detach are not counted.
	dropped tcpip.StatCounter

	pacedQueue
}

var _ stack.GSOEndpoint = (*Ingress)(nil)
var _ stack.LinkEndpoint = (*Ingress)(nil)
var _ stack.NetworkDispatcher = (*Ingress)(nil)

// NewIngress creates a new ingress TBF shaper wrapping lower. Inbound traffic
// is rate-limited to rate bytes/sec with bursts of up to burst bytes, queueing
// up to queueLen packets of backlog before dropping. As with the egress TBF,
// queueLen counts packets, not bytes. An inbound packet larger than burst
// (possible when GRO coalesces TCP segments beyond it) is not dropped; it
// passes once the bucket is completely full and drives the bucket into debt,
// preserving the sustained rate.
func NewIngress(lower stack.LinkEndpoint, clock tcpip.Clock, rate uint64, burst, queueLen uint32) (*Ingress, error) {
	buffer, err := validateConfig(lower, rate, burst, "ingress-qdisc=tbf", "ingress-qdisc-tbf-rate", "ingress-qdisc-tbf-burst")
	if err != nil {
		return nil, err
	}

	e := &Ingress{}
	e.Endpoint.Init(lower, e)
	e.start(clock, rate, buffer, queueLen, e.deliverBatch)
	return e, nil
}

// DeliverNetworkPacket implements stack.NetworkDispatcher. The lower endpoint
// calls it for each inbound packet; the packet is queued for token-bucket
// paced delivery to the dispatcher attached above this endpoint, or dropped
// if the backlog queue is full.
func (e *Ingress) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	// Some lower endpoints (e.g. xdp) carry the protocol only in the
	// argument; stash it on the packet so dispatchLoop can deliver with the
	// same protocol later, as the NIC itself would.
	pkt.NetworkProtocolNumber = protocol
	if e.enqueue(pkt) == queueFull {
		// Backlog full: drop, as Linux's sch_tbf does when limit is exceeded.
		e.dropped.Increment()
		ingressDropLogger.Warningf("ingress traffic shaping backlog full; dropping inbound packets (%d dropped on this link so far)", e.dropped.Value())
	}
}

// DroppedPackets returns the number of inbound packets dropped because the
// backlog queue was full.
func (e *Ingress) DroppedPackets() uint64 {
	return e.dropped.Value()
}

// deliverBatch hands each packet to the dispatcher attached above this
// endpoint (normally the NIC) and then drops the queue's references. Delivery
// happens outside the queue mutex because the dispatcher runs protocol
// processing inline. nested.Endpoint discards the packets if the endpoint was
// detached.
func (e *Ingress) deliverBatch(batch *stack.PacketBufferList) {
	for _, pkt := range batch.AsSlice() {
		e.Endpoint.DeliverNetworkPacket(pkt.NetworkProtocolNumber, pkt)
	}
	batch.Reset()
}

// Attach implements stack.LinkEndpoint. Attaching a nil dispatcher (detach)
// also shuts the shaper down: new deliveries are refused and the dispatch
// goroutine is told to drop the backlog and exit, but NOT joined. Every
// detach site in the stack (nic.remove via Stack.RemoveNIC, Stack.Wait, and
// checkpoint's Stack.beforeSave) runs with the stack mutex held, while the
// dispatch goroutine may itself be blocked acquiring stack locks delivering
// a packet inline (e.g. FindRoute from ICMP processing); joining here could
// deadlock the whole stack. The goroutine is joined in Close instead, which
// nic.remove runs as a deferred action after stack locks are released. Like
// fdbased, re-attaching after a detach is not supported.
func (e *Ingress) Attach(dispatcher stack.NetworkDispatcher) {
	if dispatcher == nil {
		e.signalShutdown()
	}
	e.Endpoint.Attach(dispatcher)
}

// Close implements stack.LinkEndpoint. It shuts down and joins the dispatch
// goroutine, which drops any backlog, and then closes the lower endpoint.
// The stack invokes Close without its locks held (it is a deferred action of
// nic.remove), so joining here cannot deadlock the way it could in Attach.
func (e *Ingress) Close() {
	e.signalShutdown()
	e.wg.Wait()
	e.Endpoint.Close()
}

// Wait implements stack.LinkEndpoint by waiting for the lower endpoint only.
// It deliberately does not join the shaper's dispatch goroutine: Stack.Wait
// calls Wait with the stack mutex held while the dispatch goroutine may be
// blocked acquiring stack locks to deliver a packet, so joining here could
// deadlock. Close joins the goroutine, mirroring how fdbased's processor
// goroutines are quiesced outside of Wait.
func (e *Ingress) Wait() {
	e.Endpoint.Wait()
}
