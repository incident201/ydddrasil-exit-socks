package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type SocksServer struct {
	ListenAddr string
	Net        *ExitNetStack
	DNSServers []string
}

type SocksRequest struct {
	Cmd  byte
	Host string
	Port int
	Atyp byte
}

func (s *SocksServer) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *SocksServer) handleConn(parent context.Context, client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	req, err := readSocks5Request(client)
	if err != nil {
		return
	}

	switch req.Cmd {
	case 0x01:
		s.handleConnect(parent, client, req)
	case 0x03:
		s.handleUDPAssociate(parent, client, req)
	default:
		_ = writeSocks5Reply(client, 0x07)
	}
}

func (s *SocksServer) handleConnect(parent context.Context, client net.Conn, req *SocksRequest) {
	dialCtx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()

	ips, err := ResolveAOverTCPWithFallback(dialCtx, s.Net, s.DNSServers, req.Host)
	if err != nil {
		_ = writeSocks5Reply(client, 0x04)
		log.Printf("resolve %s: %v", req.Host, err)
		return
	}

	var remote net.Conn
	var lastErr error
	for _, ip := range ips {
		remote, lastErr = s.Net.DialTCP(dialCtx, ip, req.Port)
		if lastErr == nil {
			break
		}
	}
	if remote == nil {
		_ = writeSocks5Reply(client, 0x05)
		log.Printf("connect %s:%d: %v", req.Host, req.Port, lastErr)
		return
	}
	defer remote.Close()

	_ = writeSocks5Reply(client, 0x00)
	_ = client.SetDeadline(time.Time{})
	log.Printf("SOCKS CONNECT %s:%d", req.Host, req.Port)

	proxyTCP(client, remote)
}

func readSocks5Request(conn net.Conn) (req *SocksRequest, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0x05 {
		return nil, errors.New("not SOCKS5")
	}
	nMethods := int(hdr[1])
	if nMethods <= 0 || nMethods > 255 {
		return nil, errors.New("bad methods count")
	}
	methods := make([]byte, nMethods)
	if _, err = io.ReadFull(conn, methods); err != nil {
		return nil, err
	}
	noAuth := false
	for _, m := range methods {
		if m == 0x00 {
			noAuth = true
			break
		}
	}
	if !noAuth {
		_, _ = conn.Write([]byte{0x05, 0xff})
		return nil, errors.New("SOCKS5 no acceptable auth method")
	}
	if _, err = conn.Write([]byte{0x05, 0x00}); err != nil {
		return nil, err
	}

	var rh [4]byte
	if _, err = io.ReadFull(conn, rh[:]); err != nil {
		return nil, err
	}
	if rh[0] != 0x05 {
		return nil, errors.New("bad SOCKS version in request")
	}
	if rh[2] != 0x00 {
		return nil, errors.New("bad reserved byte")
	}
	if rh[1] != 0x01 && rh[1] != 0x03 {
		_ = writeSocks5Reply(conn, 0x07)
		return nil, fmt.Errorf("unsupported SOCKS command: %d", rh[1])
	}

	req = &SocksRequest{Cmd: rh[1], Atyp: rh[3]}
	switch rh[3] {
	case 0x01:
		var b [4]byte
		if _, err = io.ReadFull(conn, b[:]); err != nil {
			return nil, err
		}
		req.Host = net.IPv4(b[0], b[1], b[2], b[3]).String()
	case 0x03:
		var lb [1]byte
		if _, err = io.ReadFull(conn, lb[:]); err != nil {
			return nil, err
		}
		l := int(lb[0])
		if l == 0 {
			return nil, errors.New("empty domain")
		}
		b := make([]byte, l)
		if _, err = io.ReadFull(conn, b); err != nil {
			return nil, err
		}
		req.Host = string(b)
	case 0x04:
		_ = writeSocks5Reply(conn, 0x08)
		return nil, errors.New("IPv6 SOCKS targets are not supported")
	default:
		_ = writeSocks5Reply(conn, 0x08)
		return nil, fmt.Errorf("unsupported address type: %d", rh[3])
	}

	var pb [2]byte
	if _, err = io.ReadFull(conn, pb[:]); err != nil {
		return nil, err
	}
	req.Port = int(binary.BigEndian.Uint16(pb[:]))
	if req.Port <= 0 || req.Port > 65535 {
		return nil, errors.New("bad port")
	}

	return req, nil
}

func writeSocks5Reply(conn net.Conn, rep byte) error {
	return writeSocks5ReplyBind(conn, rep, nil, 0)
}

func writeSocks5ReplyBind(conn net.Conn, rep byte, bindIP net.IP, bindPort int) error {
	ip4 := bindIP.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero
	}
	if bindPort <= 0 || bindPort > 65535 {
		bindPort = 0
	}
	reply := []byte{0x05, rep, 0x00, 0x01, ip4[0], ip4[1], ip4[2], ip4[3], 0, 0}
	binary.BigEndian.PutUint16(reply[8:10], uint16(bindPort))
	_, err := conn.Write(reply)
	return err
}

func proxyTCP(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		_ = closeWrite(a)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		_ = closeWrite(b)
	}()
	wg.Wait()
}

func closeWrite(c net.Conn) error {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}
