package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

var errSocksUDPFragmentUnsupported = errors.New("SOCKS5 UDP fragmentation is not supported")

type socksUDPDatagram struct {
	Host    string
	Port    int
	Payload []byte
}

type udpAssociation struct {
	server    *SocksServer
	localConn *net.UDPConn
	clientTCP net.Conn
	clientIP  net.IP

	mu        sync.Mutex
	clientUDP *net.UDPAddr
	remotes   map[udpTargetKey]*udpRemote
	dnsCache  map[string]udpDNSCacheEntry
	closed    chan struct{}
	once      sync.Once
}

type udpTargetKey struct {
	IP   string
	Port int
}

type udpRemote struct {
	key      udpTargetKey
	conn     *gonet.UDPConn
	lastUsed time.Time
}

type udpDNSCacheEntry struct {
	ip      net.IP
	expires time.Time
}

const udpDNSCacheTTL = 60 * time.Second
const udpDNSCacheMaxEntries = 1024

func (s *SocksServer) handleUDPAssociate(parent context.Context, client net.Conn, _ *SocksRequest) {
	clientTCPAddr, ok := client.RemoteAddr().(*net.TCPAddr)
	if !ok {
		_ = writeSocks5Reply(client, 0x01)
		return
	}
	clientIP := clientTCPAddr.IP.To4()
	if clientIP == nil {
		_ = writeSocks5Reply(client, 0x08)
		return
	}

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_ = writeSocks5Reply(client, 0x01)
		return
	}

	localAddr, ok := udpConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = udpConn.Close()
		_ = writeSocks5Reply(client, 0x01)
		return
	}

	if err := writeSocks5ReplyBind(client, 0x00, localAddr.IP, localAddr.Port); err != nil {
		_ = udpConn.Close()
		return
	}
	_ = client.SetDeadline(time.Time{})

	assoc := &udpAssociation{
		server:    s,
		localConn: udpConn,
		clientTCP: client,
		clientIP:  clientIP,
		remotes:   make(map[udpTargetKey]*udpRemote),
		dnsCache:  make(map[string]udpDNSCacheEntry),
		closed:    make(chan struct{}),
	}
	log.Printf("SOCKS UDP ASSOCIATE %s via %s", client.RemoteAddr(), localAddr)

	go assoc.run(parent)
	copyDone := make(chan struct{})
	go func() {
		defer close(copyDone)
		_, _ = io.Copy(io.Discard, client)
	}()

	select {
	case <-parent.Done():
	case <-copyDone:
	}
	assoc.close()
}

func (a *udpAssociation) run(parent context.Context) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := a.localConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !addr.IP.Equal(a.clientIP) {
			continue
		}

		a.mu.Lock()
		if a.clientUDP == nil {
			a.clientUDP = &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port}
		} else if !addr.IP.Equal(a.clientUDP.IP) || addr.Port != a.clientUDP.Port {
			a.mu.Unlock()
			continue
		}
		a.mu.Unlock()

		dgram, err := parseSocksUDPDatagram(buf[:n])
		if err != nil || len(dgram.Payload) == 0 {
			continue
		}

		targetIP, rErr := a.resolveTargetIP(parent, dgram.Host)
		if rErr != nil || targetIP == nil {
			continue
		}

		remote := a.getOrCreateRemote(targetIP, dgram.Port)
		if remote == nil {
			continue
		}
		remote.lastUsed = time.Now()
		_, _ = remote.conn.Write(dgram.Payload)
	}
}

func (a *udpAssociation) getOrCreateRemote(targetIP net.IP, port int) *udpRemote {
	key := udpTargetKey{IP: targetIP.String(), Port: port}

	a.mu.Lock()
	defer a.mu.Unlock()

	select {
	case <-a.closed:
		return nil
	default:
	}

	if r := a.remotes[key]; r != nil {
		return r
	}

	conn, err := a.server.Net.DialUDP(targetIP, port)
	if err != nil {
		return nil
	}
	r := &udpRemote{key: key, conn: conn, lastUsed: time.Now()}
	a.remotes[key] = r
	go a.readRemote(r)
	return r
}

func (a *udpAssociation) readRemote(remote *udpRemote) {
	defer a.removeRemote(remote.key, remote.conn)

	buf := make([]byte, 65535)
	for {
		n, err := remote.conn.Read(buf)
		if err != nil {
			return
		}

		a.mu.Lock()
		clientAddr := a.clientUDP
		a.mu.Unlock()
		if clientAddr == nil {
			continue
		}

		resp, err := buildSocksUDPDatagramIPv4(net.ParseIP(remote.key.IP), remote.key.Port, buf[:n])
		if err != nil {
			continue
		}
		_, _ = a.localConn.WriteToUDP(resp, clientAddr)
	}
}

func (a *udpAssociation) removeRemote(key udpTargetKey, conn *gonet.UDPConn) {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := a.remotes[key]
	if r == nil || r.conn != conn {
		return
	}
	_ = r.conn.Close()
	delete(a.remotes, key)
}

func (a *udpAssociation) resolveTargetIP(parent context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host).To4(); ip != nil {
		return ip, nil
	}
	cacheKey := strings.ToLower(strings.TrimSpace(host))
	a.mu.Lock()
	now := time.Now()
	if len(a.dnsCache) > udpDNSCacheMaxEntries {
		a.pruneDNSCacheLocked(now)
	}
	if cached := a.dnsCache[cacheKey]; cached.ip != nil && now.Before(cached.expires) {
		ip := append(net.IP(nil), cached.ip...)
		a.mu.Unlock()
		return ip, nil
	}
	a.mu.Unlock()

	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	ips, err := ResolveAOverTCPWithFallback(ctx, a.server.Net, a.server.DNSServers, host)
	cancel()
	if err != nil || len(ips) == 0 {
		return nil, err
	}
	ip := ips[0].To4()
	if ip == nil {
		return nil, errors.New("resolved non-IPv4 target")
	}

	a.mu.Lock()
	a.dnsCache[cacheKey] = udpDNSCacheEntry{
		ip:      append(net.IP(nil), ip...),
		expires: time.Now().Add(udpDNSCacheTTL),
	}
	a.mu.Unlock()
	return ip, nil
}

func (a *udpAssociation) pruneDNSCacheLocked(now time.Time) {
	for host, cached := range a.dnsCache {
		if !cached.expires.After(now) {
			delete(a.dnsCache, host)
		}
	}
}

func (a *udpAssociation) close() {
	a.once.Do(func() {
		close(a.closed)
		_ = a.localConn.Close()
		a.mu.Lock()
		for key, remote := range a.remotes {
			_ = remote.conn.Close()
			delete(a.remotes, key)
		}
		a.mu.Unlock()
	})
}

func parseSocksUDPDatagram(b []byte) (*socksUDPDatagram, error) {
	if len(b) < 4 {
		return nil, errors.New("short SOCKS5 UDP datagram")
	}
	if b[0] != 0x00 || b[1] != 0x00 {
		return nil, errors.New("invalid RSV")
	}
	if b[2] != 0x00 {
		return nil, errSocksUDPFragmentUnsupported
	}

	off := 4
	host := ""
	switch b[3] {
	case 0x01:
		if len(b) < off+4+2 {
			return nil, errors.New("short IPv4 SOCKS5 UDP datagram")
		}
		host = net.IPv4(b[off], b[off+1], b[off+2], b[off+3]).String()
		off += 4
	case 0x03:
		if len(b) < off+1 {
			return nil, errors.New("short domain len")
		}
		l := int(b[off])
		off++
		if l == 0 || len(b) < off+l+2 {
			return nil, errors.New("short domain SOCKS5 UDP datagram")
		}
		host = string(b[off : off+l])
		off += l
	case 0x04:
		return nil, errors.New("IPv6 SOCKS5 UDP target is not supported")
	default:
		return nil, errors.New("unsupported SOCKS5 UDP address type")
	}

	if len(b) < off+2 {
		return nil, errors.New("short port")
	}
	port := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	if port <= 0 || port > 65535 {
		return nil, errors.New("bad port")
	}

	payload := append([]byte(nil), b[off:]...)
	return &socksUDPDatagram{Host: host, Port: port, Payload: payload}, nil
}

func buildSocksUDPDatagramIPv4(srcIP net.IP, srcPort int, payload []byte) ([]byte, error) {
	ip4 := srcIP.To4()
	if ip4 == nil {
		return nil, errors.New("source IP must be IPv4")
	}
	if srcPort <= 0 || srcPort > 65535 {
		return nil, errors.New("source port out of range")
	}

	b := make([]byte, 10+len(payload))
	b[0], b[1], b[2], b[3] = 0x00, 0x00, 0x00, 0x01
	copy(b[4:8], ip4)
	binary.BigEndian.PutUint16(b[8:10], uint16(srcPort))
	copy(b[10:], payload)
	return b, nil
}
