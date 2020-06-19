// Copyright 2020 The gVisor Authors.
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

package stack

import (
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcpconntrack"
)

// Connection tracking is used to track and manipulate packets for NAT rules.
// The connection is created for a packet if it does not exist. Every
// connection contains two tuples (original and reply). The tuples are
// manipulated if there is a matching NAT rule. The packet is modified by
// looking at the tuples in the Prerouting and Output hooks.
//
// Currently, only TCP tracking is supported.

// Direction of the tuple.
type direction int

const (
	dirOriginal direction = iota
	dirReply
)

// Manipulation type for the connection.
type manipType int

const (
	manipDstPrerouting manipType = iota
	manipDstOutput
)

// tuple holds a connection's identifying and manipulating data in one
// direction.
type tuple struct {
	// conn is the connection tracking entry this tuple belongs to.
	conn *conn

	// dst is the non-manipulating part of the tuple. It is immutable.
	dst struct {
		// addr is the destination address of the tuple. It is
		// immutable.
		addr tcpip.Address

		// direction is the direction of the tuple.  It is immutable.
		direction direction

		// port is the destination port of the tuple. It is immutable.
		port uint16

		// protocol is transport layer protocol. It is immutable.
		protocol tcpip.TransportProtocolNumber
	}

	// src is manipulating part of the tuple. It is immutable.
	src struct {
		// addr is the source address of the tuple. It is immutable.
		addr tcpip.Address

		// port is the source port of the tuple. It is immutable.
		port uint16

		// protocol is the network layer protocol. It is immutable.
		protocol tcpip.NetworkProtocolNumber
	}
}

// reply creates the reply tuple.
func (tu tuple) reply() tuple {
	var replyTuple tuple
	replyTuple.src.addr = tu.dst.addr
	replyTuple.src.port = tu.dst.port
	replyTuple.src.protocol = tu.src.protocol
	replyTuple.dst.addr = tu.src.addr
	replyTuple.dst.port = tu.src.port
	replyTuple.dst.protocol = tu.dst.protocol
	replyTuple.dst.direction = dirReply
	return replyTuple
}

func (tu tuple) id() connID {
	return connID{
		srcAddr:    tu.src.addr,
		srcPort:    tu.src.port,
		dstAddr:    tu.dst.addr,
		dstPort:    tu.dst.port,
		transProto: tu.dst.protocol,
		netProto:   tu.src.protocol,
	}
}

// conn is a tracked connection.
type conn struct {
	// original is the tuple in original direction. It is immutable.
	original tuple

	// reply is the tuple in reply direction. It is immutable.
	reply tuple

	// manip indicates if the packet should be manipulated. It is immutable.
	manip manipType

	// tcbHook indicates if the packet is inbound or outbound to
	// update the state of tcb. It is immutable.
	tcbHook Hook

	// mu protects tcb.
	mu sync.Mutex

	// tcb is TCB control block. It is used to keep track of states
	// of tcp connection and is protected by mu.
	tcb tcpconntrack.TCB
}

// connID uniquely identifies a connection. It currently contains enough
// information to distinguish between any TCP or UDP connection, and will need
// to be extended to support other protocols.
type connID struct {
	srcAddr    tcpip.Address
	srcPort    uint16
	dstAddr    tcpip.Address
	dstPort    uint16
	transProto tcpip.TransportProtocolNumber
	netProto   tcpip.NetworkProtocolNumber
}

// ConnTrack tracks all connections created for NAT rules. Most users are
// expected to only call HandlePacket and CreateConnFor.
type ConnTrack struct {
	// mu protects conns.
	mu sync.RWMutex

	// conns maintains a map of tuples needed for connection tracking for
	// iptables NAT rules. It is protected by mu.
	conns map[connID]tuple
}

// packetToTuple converts packet to a tuple in original direction. It fails
// when pkt lacks a valid TCP header.
func packetToTuple(pkt *PacketBuffer) (tuple, *tcpip.Error) {
	var tuple tuple

	// TODO(gvisor.dev/issue/170): Need to support for other
	// protocols as well.
	netHeader := header.IPv4(pkt.NetworkHeader)
	if netHeader == nil || netHeader.TransportProtocol() != header.TCPProtocolNumber {
		return tuple, tcpip.ErrUnknownProtocol
	}
	tcpHeader := header.TCP(pkt.TransportHeader)
	if tcpHeader == nil {
		return tuple, tcpip.ErrUnknownProtocol
	}

	tuple.src.addr = netHeader.SourceAddress()
	tuple.src.port = tcpHeader.SourcePort()
	tuple.src.protocol = header.IPv4ProtocolNumber

	tuple.dst.addr = netHeader.DestinationAddress()
	tuple.dst.port = tcpHeader.DestinationPort()
	tuple.dst.protocol = netHeader.TransportProtocol()

	return tuple, nil
}

// newConn creates new connection.
func newConn(orig, reply tuple, manip manipType, hook Hook) *conn {
	conn := conn{
		original: orig,
		reply:    reply,
		manip:    manip,
		tcbHook:  hook,
	}
	conn.original.conn = &conn
	conn.reply.conn = &conn
	return &conn
}

// connFor gets the conn for pkt if it exists, or returns nil
// if it does not. It returns an error when pkt does not contain a valid TCP
// header.
// TODO(gvisor.dev/issue/170): Only TCP packets are supported. Need to support
// other transport protocols.
func (ct *ConnTrack) connFor(pkt *PacketBuffer) (*conn, direction) {
	tuple, err := packetToTuple(pkt)
	if err != nil {
		return nil, dirOriginal
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	tuple, ok := ct.conns[tuple.id()]
	if !ok {
		return nil, dirOriginal
	}
	return tuple.conn, tuple.dst.direction
}

// CreateConnFor creates a new conn for pkt.
func (ct *ConnTrack) CreateConnFor(pkt *PacketBuffer, hook Hook, rt RedirectTarget) *conn {
	tuple, err := packetToTuple(pkt)
	if err != nil {
		return nil
	}
	if hook != Prerouting && hook != Output {
		return nil
	}

	// Create a new connection and change the port as per the iptables
	// rule. This tuple will be used to manipulate the packet in
	// HandlePacket.
	replyTuple := tuple.reply()
	replyTuple.src.addr = rt.MinIP
	replyTuple.src.port = rt.MinPort
	var manip manipType
	switch hook {
	case Prerouting:
		manip = manipDstPrerouting
	case Output:
		manip = manipDstOutput
	}
	conn := newConn(tuple, replyTuple, manip, hook)

	// Add the changed tuple to the map.
	// TODO(gvisor.dev/issue/170): Need to support collisions using linked
	// list.
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.conns[tuple.id()] = conn.original
	ct.conns[replyTuple.id()] = conn.reply

	return conn
}

// handlePacketPrerouting manipulates ports for packets in Prerouting hook.
// TODO(gvisor.dev/issue/170): Change address for Prerouting hook.
func handlePacketPrerouting(pkt *PacketBuffer, conn *conn, dir direction) {
	netHeader := header.IPv4(pkt.NetworkHeader)
	tcpHeader := header.TCP(pkt.TransportHeader)

	// For prerouting redirection, packets going in the original direction
	// have their destinations modified and replies have their sources
	// modified.
	switch dir {
	case dirOriginal:
		port := conn.reply.src.port
		tcpHeader.SetDestinationPort(port)
		netHeader.SetDestinationAddress(conn.reply.src.addr)
	case dirReply:
		port := conn.original.dst.port
		tcpHeader.SetSourcePort(port)
		netHeader.SetSourceAddress(conn.original.dst.addr)
	}

	netHeader.SetChecksum(0)
	netHeader.SetChecksum(^netHeader.CalculateChecksum())
}

// handlePacketOutput manipulates ports for packets in Output hook.
func handlePacketOutput(pkt *PacketBuffer, conn *conn, gso *GSO, r *Route, dir direction) {
	netHeader := header.IPv4(pkt.NetworkHeader)
	tcpHeader := header.TCP(pkt.TransportHeader)

	// For output redirection, packets going in the original direction
	// have their destinations modified and replies have their sources
	// modified. For prerouting redirection, we only reach this point
	// when replying, so packet sources are modified.
	if conn.manip == manipDstOutput && dir == dirOriginal {
		port := conn.reply.src.port
		tcpHeader.SetDestinationPort(port)
		netHeader.SetDestinationAddress(conn.reply.src.addr)
	} else {
		port := conn.original.dst.port
		tcpHeader.SetSourcePort(port)
		netHeader.SetSourceAddress(conn.original.dst.addr)
	}

	// Calculate the TCP checksum and set it.
	tcpHeader.SetChecksum(0)
	hdr := &pkt.Header
	length := uint16(pkt.Data.Size()+hdr.UsedLength()) - uint16(netHeader.HeaderLength())
	xsum := r.PseudoHeaderChecksum(header.TCPProtocolNumber, length)
	if gso != nil && gso.NeedsCsum {
		tcpHeader.SetChecksum(xsum)
	} else if r.Capabilities()&CapabilityTXChecksumOffload == 0 {
		xsum = header.ChecksumVVWithOffset(pkt.Data, xsum, int(tcpHeader.DataOffset()), pkt.Data.Size())
		tcpHeader.SetChecksum(^tcpHeader.CalculateChecksum(xsum))
	}

	netHeader.SetChecksum(0)
	netHeader.SetChecksum(^netHeader.CalculateChecksum())
}

// HandlePacket will manipulate the port and address of the packet if the
// connection exists.
func (ct *ConnTrack) HandlePacket(pkt *PacketBuffer, hook Hook, gso *GSO, r *Route) {
	if pkt.NatDone {
		return
	}

	if hook != Prerouting && hook != Output {
		return
	}

	conn, dir := ct.connFor(pkt)
	if conn == nil {
		// Connection not found for the packet or the packet is invalid.
		return
	}

	switch hook {
	case Prerouting:
		handlePacketPrerouting(pkt, conn, dir)
	case Output:
		handlePacketOutput(pkt, conn, gso, r, dir)
	}
	pkt.NatDone = true

	// Update the state of tcb.
	// TODO(gvisor.dev/issue/170): Add support in tcpcontrack to handle
	// other tcp states.
	conn.mu.Lock()
	defer conn.mu.Unlock()
	var st tcpconntrack.Result
	tcpHeader := header.TCP(pkt.TransportHeader)
	if conn.tcb.IsEmpty() {
		conn.tcb.Init(tcpHeader)
		conn.tcbHook = hook
	} else {
		switch hook {
		case conn.tcbHook:
			st = conn.tcb.UpdateStateOutbound(tcpHeader)
		default:
			st = conn.tcb.UpdateStateInbound(tcpHeader)
		}
	}

	// Delete conn if tcp connection is closed.
	if st == tcpconntrack.ResultClosedByPeer || st == tcpconntrack.ResultClosedBySelf || st == tcpconntrack.ResultReset {
		ct.deleteConn(conn)
	}
}

// deleteConn deletes the connection.
func (ct *ConnTrack) deleteConn(conn *conn) {
	if conn == nil {
		return
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	delete(ct.conns, conn.original.id())
	delete(ct.conns, conn.reply.id())
}
