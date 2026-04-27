package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const nicID tcpip.NICID = 1

type ExitNetStack struct {
	stack *stack.Stack
	nic   *exitNIC
}

func NewExitNetStack(tunnel *ExitTunnel, innerIP string, prefixLen int, mtu int) (*ExitNetStack, error) {
	ip4 := net.ParseIP(innerIP).To4()
	if ip4 == nil {
		return nil, fmt.Errorf("inner IP must be IPv4: %q", innerIP)
	}
	if mtu <= 0 {
		mtu = 1280
	}

	s := &ExitNetStack{
		stack: stack.New(stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{
				tcp.NewProtocol,
				udp.NewProtocol,
			},
			HandleLocal: true,
		}),
	}

	nic := &exitNIC{
		owner:      s,
		tunnel:     tunnel,
		readBuf:    make([]byte, mtu),
		writeBuf:   make([]byte, mtu),
		configured: mtu,
	}
	s.nic = nic

	if err := s.stack.CreateNIC(nicID, nic); err != nil {
		return nil, fmt.Errorf("CreateNIC: %s", err.String())
	}

	protoAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(ip4),
			PrefixLen: prefixLen,
		},
	}
	if err := s.stack.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("AddProtocolAddress: %s", err.String())
	}

	s.stack.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         nicID,
	}})

	go nic.readLoop()
	return s, nil
}

func (s *ExitNetStack) Close() {
	if s.nic != nil {
		s.nic.Close()
	}
}

func (s *ExitNetStack) DialTCP(ctx context.Context, ip net.IP, port int) (net.Conn, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("only IPv4 targets are supported: %s", ip)
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("port out of range: %d", port)
	}
	fa := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(ip4),
		Port: uint16(port),
	}
	return gonet.DialContextTCP(ctx, s.stack, fa, ipv4.ProtocolNumber)
}

func (s *ExitNetStack) DialUDP(ip net.IP, port int) (*gonet.UDPConn, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("only IPv4 targets are supported: %s", ip)
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("port out of range: %d", port)
	}
	fa := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(ip4),
		Port: uint16(port),
	}
	return gonet.DialUDP(s.stack, nil, &fa, ipv4.ProtocolNumber)
}

type exitNIC struct {
	owner      *ExitNetStack
	tunnel     *ExitTunnel
	dispatcher stack.NetworkDispatcher
	readBuf    []byte
	writeBuf   []byte
	configured int
}

func (e *exitNIC) readLoop() {
	for {
		n, err := e.tunnel.ReadPacket(e.readBuf)
		if err != nil {
			log.Printf("exit tunnel read failed: %v", err)
			return
		}
		if n <= 0 {
			continue
		}
		if e.dispatcher == nil {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(e.readBuf[:n]),
		})
		e.dispatcher.DeliverNetworkPacket(ipv4.ProtocolNumber, pkb)
		pkb.DecRef()
	}
}

func (e *exitNIC) Attach(dispatcher stack.NetworkDispatcher)  { e.dispatcher = dispatcher }
func (e *exitNIC) IsAttached() bool                           { return e.dispatcher != nil }
func (e *exitNIC) MTU() uint32                                { return uint32(e.configured) }
func (e *exitNIC) SetMTU(mtu uint32)                          { e.configured = int(mtu) }
func (*exitNIC) Capabilities() stack.LinkEndpointCapabilities { return stack.CapabilityNone }
func (*exitNIC) MaxHeaderLength() uint16                      { return 0 }
func (*exitNIC) LinkAddress() tcpip.LinkAddress               { return "" }
func (*exitNIC) SetLinkAddress(tcpip.LinkAddress)             {}
func (*exitNIC) Wait()                                        {}
func (*exitNIC) ARPHardwareType() header.ARPHardwareType      { return header.ARPHardwareNone }
func (*exitNIC) AddHeader(*stack.PacketBuffer)                {}
func (*exitNIC) ParseHeader(*stack.PacketBuffer) bool         { return true }
func (*exitNIC) SetOnCloseAction(func())                      {}

func (e *exitNIC) Close() {
	if e.owner != nil && e.owner.stack != nil {
		e.owner.stack.RemoveNIC(nicID)
	}
	e.dispatcher = nil
}

func (e *exitNIC) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	sent := 0
	for _, pkt := range list.AsSlice() {
		if err := e.writePacket(pkt); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

func (e *exitNIC) WriteRawPacket(pkt *stack.PacketBuffer) tcpip.Error { return e.writePacket(pkt) }

func (e *exitNIC) writePacket(pkt *stack.PacketBuffer) (ret tcpip.Error) {
	defer func() {
		if r := recover(); r != nil {
			ret = &tcpip.ErrAborted{}
		}
	}()

	vv := pkt.ToView()
	n, err := vv.Read(e.writeBuf)
	if err != nil {
		return &tcpip.ErrAborted{}
	}
	if n <= 0 {
		return nil
	}
	if err := e.tunnel.WritePacket(e.writeBuf[:n]); err != nil {
		return &tcpip.ErrAborted{}
	}
	return nil
}
