package main

import (
	"bytes"
	"errors"
	"net"
	"testing"
)

func TestParseSocksUDPDatagramIPv4(t *testing.T) {
	raw := []byte{0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35, 'a', 'b'}
	d, err := parseSocksUDPDatagram(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if d.Host != "8.8.8.8" || d.Port != 53 {
		t.Fatalf("bad target: %+v", d)
	}
	if !bytes.Equal(d.Payload, []byte{'a', 'b'}) {
		t.Fatalf("bad payload: %x", d.Payload)
	}
}

func TestParseSocksUDPDatagramDomain(t *testing.T) {
	raw := []byte{0x00, 0x00, 0x00, 0x03, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb, 0x10}
	d, err := parseSocksUDPDatagram(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if d.Host != "example.com" || d.Port != 443 {
		t.Fatalf("bad target: %+v", d)
	}
	if !bytes.Equal(d.Payload, []byte{0x10}) {
		t.Fatalf("bad payload: %x", d.Payload)
	}
}

func TestParseSocksUDPDatagramFragUnsupported(t *testing.T) {
	raw := []byte{0x00, 0x00, 0x01, 0x01, 1, 1, 1, 1, 0, 53}
	_, err := parseSocksUDPDatagram(raw)
	if !errors.Is(err, errSocksUDPFragmentUnsupported) {
		t.Fatalf("expected fragment unsupported, got: %v", err)
	}
}

func TestBuildSocksUDPDatagramIPv4(t *testing.T) {
	payload := []byte{0xde, 0xad}
	b, err := buildSocksUDPDatagramIPv4(net.IPv4(1, 1, 1, 1), 1234, payload)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	want := []byte{0x00, 0x00, 0x00, 0x01, 1, 1, 1, 1, 0x04, 0xd2, 0xde, 0xad}
	if !bytes.Equal(b, want) {
		t.Fatalf("unexpected datagram: %x", b)
	}
}
