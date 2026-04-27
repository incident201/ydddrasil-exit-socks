package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

type SocksServer struct {
	ListenAddr string
	Net        *ExitNetStack
	DNSServer  string
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

	targetHost, targetPort, err := readSocks5Connect(client)
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()

	ips, err := ResolveAOverTCP(ctx, s.Net, s.DNSServer, targetHost)
	if err != nil {
		_ = writeSocks5Reply(client, 0x04) // host unreachable
		log.Printf("resolve %s: %v", targetHost, err)
		return
	}

	var remote net.Conn
	var lastErr error
	for _, ip := range ips {
		remote, lastErr = s.Net.DialTCP(ctx, ip, targetPort)
		if lastErr == nil {
			break
		}
	}
	if remote == nil {
		_ = writeSocks5Reply(client, 0x05) // connection refused / failed
		log.Printf("connect %s:%d: %v", targetHost, targetPort, lastErr)
		return
	}
	defer remote.Close()

	_ = writeSocks5Reply(client, 0x00)
	_ = client.SetDeadline(time.Time{})
	log.Printf("SOCKS CONNECT %s:%d", targetHost, targetPort)

	proxyTCP(client, remote)
}

func readSocks5Connect(conn net.Conn) (host string, port int, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(conn, hdr[:]); err != nil {
		return "", 0, err
	}
	if hdr[0] != 0x05 {
		return "", 0, errors.New("not SOCKS5")
	}
	nMethods := int(hdr[1])
	if nMethods <= 0 || nMethods > 255 {
		return "", 0, errors.New("bad methods count")
	}
	methods := make([]byte, nMethods)
	if _, err = io.ReadFull(conn, methods); err != nil {
		return "", 0, err
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
		return "", 0, errors.New("SOCKS5 no acceptable auth method")
	}
	if _, err = conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", 0, err
	}

	var req [4]byte
	if _, err = io.ReadFull(conn, req[:]); err != nil {
		return "", 0, err
	}
	if req[0] != 0x05 {
		return "", 0, errors.New("bad SOCKS version in request")
	}
	if req[1] != 0x01 {
		_ = writeSocks5Reply(conn, 0x07) // command not supported
		return "", 0, errors.New("only CONNECT is supported")
	}
	if req[2] != 0x00 {
		return "", 0, errors.New("bad reserved byte")
	}

	switch req[3] {
	case 0x01: // IPv4
		var b [4]byte
		if _, err = io.ReadFull(conn, b[:]); err != nil {
			return "", 0, err
		}
		host = net.IPv4(b[0], b[1], b[2], b[3]).String()
	case 0x03: // domain
		var lb [1]byte
		if _, err = io.ReadFull(conn, lb[:]); err != nil {
			return "", 0, err
		}
		l := int(lb[0])
		if l == 0 {
			return "", 0, errors.New("empty domain")
		}
		b := make([]byte, l)
		if _, err = io.ReadFull(conn, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	case 0x04: // IPv6
		_ = writeSocks5Reply(conn, 0x08) // address type not supported
		return "", 0, errors.New("IPv6 SOCKS targets are not supported")
	default:
		_ = writeSocks5Reply(conn, 0x08)
		return "", 0, fmt.Errorf("unsupported address type: %d", req[3])
	}

	var pb [2]byte
	if _, err = io.ReadFull(conn, pb[:]); err != nil {
		return "", 0, err
	}
	port = int(binary.BigEndian.Uint16(pb[:]))
	if port <= 0 || port > 65535 {
		return "", 0, errors.New("bad port")
	}
	return host, port, nil
}

func writeSocks5Reply(conn net.Conn, rep byte) error {
	// VER, REP, RSV, ATYP IPv4, BND.ADDR 0.0.0.0, BND.PORT 0
	_, err := conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
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

func hostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
