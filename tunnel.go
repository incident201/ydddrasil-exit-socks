package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	ipv6HeaderLen = 40
	udpHeaderLen  = 8
	udpProto      = 17
)

type ExitTunnel struct {
	node       *YggNode
	localIP    net.IP
	remoteIP   net.IP
	localPort  uint16
	remotePort uint16
	mtu        int
}

func NewExitTunnel(node *YggNode, remoteAddr string, remotePort int, localPort int, mtu int) (*ExitTunnel, error) {
	if node == nil || node.core == nil || node.iprwc == nil {
		return nil, errors.New("yggdrasil node is not started")
	}
	if remotePort <= 0 || remotePort > 65535 {
		return nil, fmt.Errorf("remote port out of range: %d", remotePort)
	}
	if localPort <= 0 || localPort > 65535 {
		return nil, fmt.Errorf("local port out of range: %d", localPort)
	}
	remoteIP := net.ParseIP(remoteAddr)
	if remoteIP == nil || remoteIP.To4() != nil || remoteIP.To16() == nil {
		return nil, fmt.Errorf("remote address must be IPv6: %s", remoteAddr)
	}
	localIP := node.Address().To16()
	if localIP == nil || node.Address().To4() != nil {
		return nil, fmt.Errorf("local yggdrasil address is not IPv6")
	}
	if mtu <= 0 {
		mtu = node.iprwc.MTU()
	}
	if node.iprwc.MTU() < mtu {
		mtu = node.iprwc.MTU()
	}

	return &ExitTunnel{
		node:       node,
		localIP:    append(net.IP(nil), localIP...),
		remoteIP:   append(net.IP(nil), remoteIP.To16()...),
		localPort:  uint16(localPort),
		remotePort: uint16(remotePort),
		mtu:        mtu,
	}, nil
}

func (t *ExitTunnel) WritePacket(payload []byte) error {
	packet, err := buildIPv6UDPPacket(t.localIP, t.remoteIP, t.localPort, t.remotePort, payload, t.mtu)
	if err != nil {
		return err
	}
	t.node.mu.Lock()
	defer t.node.mu.Unlock()
	n, err := t.node.iprwc.Write(packet)
	if err != nil {
		return err
	}
	if n != len(packet) {
		return fmt.Errorf("short write: %d/%d", n, len(packet))
	}
	return nil
}

func (t *ExitTunnel) ReadPacket(buf []byte) (int, error) {
	packetBuf := make([]byte, 65535)
	for {
		n, err := t.node.iprwc.Read(packetBuf)
		if err != nil {
			return 0, err
		}
		payload, match, err := parseMatchingTunnelPayload(packetBuf[:n], t.localIP, t.remoteIP, t.localPort, t.remotePort)
		if err != nil || !match {
			continue
		}
		if len(payload) > len(buf) {
			return 0, fmt.Errorf("payload size %d exceeds buffer size %d", len(payload), len(buf))
		}
		copy(buf, payload)
		return len(payload), nil
	}
}

func buildIPv6UDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte, mtu int) ([]byte, error) {
	src := srcIP.To16()
	dst := dstIP.To16()
	if src == nil || dst == nil || srcIP.To4() != nil || dstIP.To4() != nil {
		return nil, errors.New("src/dst must be IPv6 addresses")
	}
	udpLen := udpHeaderLen + len(payload)
	if udpLen > 65535 {
		return nil, fmt.Errorf("UDP payload too large: %d", len(payload))
	}
	totalLen := ipv6HeaderLen + udpLen
	if mtu > 0 && totalLen > mtu {
		return nil, fmt.Errorf("packet size %d exceeds MTU %d", totalLen, mtu)
	}

	packet := make([]byte, totalLen)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(udpLen))
	packet[6] = udpProto
	packet[7] = 64
	copy(packet[8:24], src)
	copy(packet[24:40], dst)

	udp := packet[ipv6HeaderLen:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[udpHeaderLen:], payload)

	checksum := udpChecksum(packet[8:24], packet[24:40], udp)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return packet, nil
}

func parseMatchingTunnelPayload(packet []byte, localIP, remoteIP net.IP, localPort, remotePort uint16) ([]byte, bool, error) {
	if len(packet) < ipv6HeaderLen+udpHeaderLen {
		return nil, false, errors.New("packet too short")
	}
	if packet[0]>>4 != 6 {
		return nil, false, errors.New("not an IPv6 packet")
	}
	if packet[6] != udpProto {
		return nil, false, errors.New("not a UDP packet")
	}

	ipv6PayloadLen := int(binary.BigEndian.Uint16(packet[4:6]))
	if ipv6PayloadLen < udpHeaderLen || len(packet) < ipv6HeaderLen+ipv6PayloadLen {
		return nil, false, errors.New("invalid IPv6 payload length")
	}
	udp := packet[ipv6HeaderLen : ipv6HeaderLen+ipv6PayloadLen]
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < udpHeaderLen || udpLen > len(udp) {
		return nil, false, errors.New("invalid UDP length")
	}
	udp = udp[:udpLen]

	if udpChecksum(packet[8:24], packet[24:40], udp) != 0 {
		return nil, false, errors.New("invalid UDP checksum")
	}

	src := net.IP(packet[8:24])
	dst := net.IP(packet[24:40])
	srcPort := binary.BigEndian.Uint16(udp[0:2])
	dstPort := binary.BigEndian.Uint16(udp[2:4])

	if !dst.Equal(localIP) || !src.Equal(remoteIP) || srcPort != remotePort || dstPort != localPort {
		return nil, false, nil
	}

	return udp[udpHeaderLen:], true, nil
}

func udpChecksum(src, dst, udp []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(src[i : i+2]))
		sum += uint32(binary.BigEndian.Uint16(dst[i : i+2]))
	}
	sum += uint32(len(udp))
	sum += uint32(udpProto)

	for i := 0; i+1 < len(udp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udp[i : i+2]))
	}
	if len(udp)%2 == 1 {
		sum += uint32(udp[len(udp)-1]) << 8
	}

	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
