package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

func ResolveAOverTCP(ctx context.Context, ns *ExitNetStack, dnsServer string, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return []net.IP{ip4}, nil
		}
		return nil, fmt.Errorf("IPv6 targets are not supported: %s", host)
	}

	dnsIP := net.ParseIP(dnsServer).To4()
	if dnsIP == nil {
		return nil, fmt.Errorf("DNS server must be IPv4: %s", dnsServer)
	}

	query, id, err := buildDNSQueryA(host)
	if err != nil {
		return nil, err
	}

	conn, err := ns.DialTCP(ctx, dnsIP, 53)
	if err != nil {
		return nil, fmt.Errorf("dial DNS %s: %w", dnsServer, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	if _, err := conn.Write(frame); err != nil {
		return nil, fmt.Errorf("write DNS query: %w", err)
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read DNS length: %w", err)
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if respLen < 12 || respLen > 4096 {
		return nil, fmt.Errorf("bad DNS response length: %d", respLen)
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("read DNS response: %w", err)
	}

	ips, err := parseDNSResponseA(resp, id)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no A records for %s", host)
	}
	return ips, nil
}

func buildDNSQueryA(host string) ([]byte, uint16, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return nil, 0, errors.New("empty DNS host")
	}

	var idBuf [2]byte
	if _, err := rand.Read(idBuf[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(idBuf[:])

	qname := make([]byte, 0, len(host)+2)
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return nil, 0, fmt.Errorf("invalid DNS label in %q", host)
		}
		qname = append(qname, byte(len(label)))
		qname = append(qname, label...)
	}
	qname = append(qname, 0)

	msg := make([]byte, 12, 12+len(qname)+4)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(msg[4:6], 1)      // QDCOUNT
	msg = append(msg, qname...)
	msg = append(msg, 0x00, 0x01) // QTYPE A
	msg = append(msg, 0x00, 0x01) // QCLASS IN
	return msg, id, nil
}

func parseDNSResponseA(msg []byte, wantID uint16) ([]net.IP, error) {
	if len(msg) < 12 {
		return nil, errors.New("short DNS response")
	}
	if binary.BigEndian.Uint16(msg[0:2]) != wantID {
		return nil, errors.New("DNS response id mismatch")
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 == 0 {
		return nil, errors.New("not a DNS response")
	}
	if rcode := flags & 0x000f; rcode != 0 {
		return nil, fmt.Errorf("DNS error rcode=%d", rcode)
	}

	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	var err error
	for i := 0; i < qd; i++ {
		off, err = skipDNSName(msg, off)
		if err != nil {
			return nil, err
		}
		if off+4 > len(msg) {
			return nil, errors.New("bad DNS question")
		}
		off += 4
	}

	var ips []net.IP
	for i := 0; i < an; i++ {
		off, err = skipDNSName(msg, off)
		if err != nil {
			return nil, err
		}
		if off+10 > len(msg) {
			return nil, errors.New("bad DNS answer")
		}
		rrType := binary.BigEndian.Uint16(msg[off : off+2])
		rrClass := binary.BigEndian.Uint16(msg[off+2 : off+4])
		rdLen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdLen > len(msg) {
			return nil, errors.New("bad DNS rdata")
		}
		if rrType == 1 && rrClass == 1 && rdLen == 4 { // A IN
			ips = append(ips, net.IPv4(msg[off], msg[off+1], msg[off+2], msg[off+3]).To4())
		}
		off += rdLen
	}
	return ips, nil
}

func skipDNSName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, errors.New("bad DNS name")
		}
		l := int(msg[off])
		off++
		switch l & 0xc0 {
		case 0x00:
			if l == 0 {
				return off, nil
			}
			if off+l > len(msg) {
				return 0, errors.New("bad DNS label")
			}
			off += l
		case 0xc0:
			if off >= len(msg) {
				return 0, errors.New("bad DNS compression pointer")
			}
			return off + 1, nil
		default:
			return 0, errors.New("unsupported DNS name encoding")
		}
	}
}
