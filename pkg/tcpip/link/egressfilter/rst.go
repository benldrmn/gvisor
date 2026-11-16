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
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// responseTTL is the IP TTL / hop limit of a synthesized reset.
const responseTTL = 64

// synthesizeRST builds an inbound reset for a blocked outbound TCP segment,
// following RFC 9293 section 3.10.7.1. It leaves pkt unchanged and returns nil
// for non-TCP packets, resets, or missing or invalid headers.
//
// It requires parsed transport headers, excluding raw and packet sockets.
// The caller must DecRef a returned packet.
func synthesizeRST(pkt *stack.PacketBuffer, l4proto uint8) (*stack.PacketBuffer, tcpip.NetworkProtocolNumber) {
	if l4proto != uint8(header.TCPProtocolNumber) {
		return nil, 0
	}
	nh := pkt.NetworkHeader().Slice()
	th := pkt.TransportHeader().Slice()
	if len(nh) == 0 || len(th) < header.TCPMinimumSize {
		return nil, 0
	}
	seg := header.TCP(th)
	if seg.Flags().Contains(header.TCPFlagRst) {
		return nil, 0
	}

	// The reset reverses the outbound packet's addresses and ports.
	var srcAddr, dstAddr tcpip.Address
	var netProto tcpip.NetworkProtocolNumber
	switch header.IPVersion(nh) {
	case header.IPv4Version:
		if len(nh) < header.IPv4MinimumSize {
			return nil, 0
		}
		ip := header.IPv4(nh)
		srcAddr, dstAddr = ip.SourceAddress(), ip.DestinationAddress()
		netProto = header.IPv4ProtocolNumber
	case header.IPv6Version:
		if len(nh) < header.IPv6MinimumSize {
			return nil, 0
		}
		ip := header.IPv6(nh)
		srcAddr, dstAddr = ip.SourceAddress(), ip.DestinationAddress()
		netProto = header.IPv6ProtocolNumber
	default:
		return nil, 0
	}

	var seqNum, ackNum uint32
	flags := header.TCPFlagRst
	if seg.Flags().Contains(header.TCPFlagAck) {
		seqNum = seg.AckNumber()
	} else {
		flags |= header.TCPFlagAck
		// SYN and FIN each consume one sequence number.
		logicalLen := uint32(pkt.Data().Size())
		if seg.Flags().Contains(header.TCPFlagSyn) {
			logicalLen++
		}
		if seg.Flags().Contains(header.TCPFlagFin) {
			logicalLen++
		}
		ackNum = seg.SequenceNumber() + logicalLen
	}

	const tcpLen = header.TCPMinimumSize
	var b []byte
	var tcp header.TCP
	switch netProto {
	case header.IPv4ProtocolNumber:
		b = make([]byte, header.IPv4MinimumSize+tcpLen)
		ip := header.IPv4(b)
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(len(b)),
			TTL:         responseTTL,
			Protocol:    uint8(header.TCPProtocolNumber),
			SrcAddr:     dstAddr,
			DstAddr:     srcAddr,
		})
		ip.SetChecksum(^ip.CalculateChecksum())
		tcp = header.TCP(b[header.IPv4MinimumSize:])
	case header.IPv6ProtocolNumber:
		b = make([]byte, header.IPv6MinimumSize+tcpLen)
		ip := header.IPv6(b)
		ip.Encode(&header.IPv6Fields{
			PayloadLength:     tcpLen,
			TransportProtocol: header.TCPProtocolNumber,
			HopLimit:          responseTTL,
			SrcAddr:           dstAddr,
			DstAddr:           srcAddr,
		})
		tcp = header.TCP(b[header.IPv6MinimumSize:])
	}
	tcp.Encode(&header.TCPFields{
		SrcPort:    seg.DestinationPort(),
		DstPort:    seg.SourcePort(),
		SeqNum:     seqNum,
		AckNum:     ackNum,
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
		WindowSize: 0,
	})
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, dstAddr, srcAddr, tcpLen)
	tcp.SetChecksum(^tcp.CalculateChecksum(xsum))

	resp := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
	resp.NetworkProtocolNumber = netProto
	return resp, netProto
}
