// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later
// https://github.com/fmuecke/allowproxy

package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
)

// alertAccessDenied is a fatal TLS access_denied alert. It tells a client
// whose ClientHello was refused why the tunnel ends.
var alertAccessDenied = []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x31}

// checkClientHello reads the TLS ClientHello that opens a tunnel and checks
// that its server name (SNI) is the host of the CONNECT target. Otherwise a
// tunnel to an allowed host could ask servers shared with other sites, such
// as a CDN, for one of those. An IP target must come without a server name.
// Encrypted Client Hello is refused: its visible server name is an outer one
// that the client picks, while the server answers for the encrypted inner one.
// It returns all bytes read, which still have to reach the server.
func checkClientHello(r io.Reader, target string) ([]byte, error) {
	host, _, _ := net.SplitHostPort(target)
	info, hello, err := readClientHello(r)
	if err != nil {
		return nil, err
	}
	if slices.Contains(info.Extensions, extensionECH) {
		return nil, errors.New("encrypted client hello is not allowed")
	}
	name := info.ServerName
	if _, err := netip.ParseAddr(host); err == nil {
		if name != "" {
			return nil, fmt.Errorf("tls server name %q for an IP target", name)
		}
		return hello, nil
	}
	if normalized, ok := normalizeHostname(name); !ok || normalized != host {
		return nil, fmt.Errorf("tls server name %q does not match the target", name)
	}
	return hello, nil
}

// extensionECH is the TLS extension that carries an Encrypted Client Hello
// (RFC 9849). Clients without an ECH config may send it as GREASE, which
// can't be told apart from a real one.
const extensionECH = 0xfe0d

var errHelloRead = errors.New("client hello read")

// readClientHello reads a TLS ClientHello from r and returns what Go's TLS
// server parsed from it, and the bytes read. The handshake stops right after
// the ClientHello.
func readClientHello(r io.Reader) (info *tls.ClientHelloInfo, hello []byte, err error) {
	var read bytes.Buffer
	err = tls.Server(helloConn{r: io.TeeReader(r, &read)}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			info = h
			return nil, errHelloRead
		},
	}).Handshake()
	if info == nil {
		return nil, nil, fmt.Errorf("no tls client hello: %w", err)
	}
	return info, read.Bytes(), nil
}

// helloConn feeds the client's bytes to the TLS parser and discards what it
// writes back, because the real server answers the handshake.
type helloConn struct {
	net.Conn // nil; tls.Server uses only Read and Write
	r        io.Reader
}

func (c helloConn) Read(b []byte) (int, error)  { return c.r.Read(b) }
func (c helloConn) Write(b []byte) (int, error) { return len(b), nil }
