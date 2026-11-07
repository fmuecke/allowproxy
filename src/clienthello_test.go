// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later
// https://github.com/fmuecke/allowproxy

package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// clientHello returns the ClientHello that Go's TLS client sends for
// serverName; an empty name sends none.
func clientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	return clientHelloWith(t, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
}

// clientHelloWith returns the ClientHello that Go's TLS client sends for config.
func clientHelloWith(t *testing.T, config *tls.Config) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	go tls.Client(client, config).Handshake()
	defer client.Close()
	buf := make([]byte, 64<<10)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func TestCheckClientHello(t *testing.T) {
	for _, tc := range []struct {
		serverName, target string
		ok                 bool
	}{
		{"github.com", "github.com:443", true},
		{"GitHub.com", "github.com:443", true},
		{"api.github.com", "github.com:443", false},
		{"github.com", "api.github.com:443", false},
		{"", "github.com:443", false},
		{"", "140.82.112.3:443", true},
		{"", "[2001:db8::1]:443", true},
		{"github.com", "140.82.112.3:443", false},
	} {
		hello := clientHello(t, tc.serverName)
		// Bytes after the ClientHello are either returned or left in the reader.
		r := bytes.NewReader(append(hello, "next"...))
		got, err := checkClientHello(r, tc.target)
		if (err == nil) != tc.ok {
			t.Errorf("server name %q, target %s: error %v, want ok=%v", tc.serverName, tc.target, err, tc.ok)
			continue
		}
		rest, _ := io.ReadAll(r)
		if tc.ok && string(append(got, rest...)) != string(hello)+"next" {
			t.Errorf("server name %q: bytes were lost or changed", tc.serverName)
		}
	}
}

// echConfigList returns a serialized ECHConfigList (RFC 9849) for publicName
// with a fresh X25519 key, using HKDF-SHA256 and AES-128-GCM.
func echConfigList(t *testing.T, publicName string) []byte {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	prefix16 := func(b []byte) []byte { return append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...) }
	contents := []byte{1, 0x00, 0x20} // config_id, DHKEM(X25519, HKDF-SHA256)
	contents = append(contents, prefix16(key.PublicKey().Bytes())...)
	contents = append(contents, prefix16([]byte{0x00, 0x01, 0x00, 0x01})...) // HKDF-SHA256, AES-128-GCM
	contents = append(contents, 0, byte(len(publicName)))                    // maximum_name_length, public_name
	contents = append(contents, publicName...)
	contents = append(contents, 0, 0) // no extensions
	config := append([]byte{0xfe, 0x0d}, prefix16(contents)...)
	return prefix16(config)
}

// With Encrypted Client Hello, the visible server name is only the outer one,
// which the client picks; the server answers for the encrypted inner one.
func TestCheckClientHelloRejectsECH(t *testing.T) {
	hello := clientHelloWith(t, &tls.Config{
		ServerName:                     "blocked.example",
		EncryptedClientHelloConfigList: echConfigList(t, "github.com"),
		MinVersion:                     tls.VersionTLS13,
	})
	if _, err := checkClientHello(bytes.NewReader(hello), "github.com:443"); err == nil || !strings.Contains(err.Error(), "encrypted client hello") {
		t.Errorf("ECH with an allowed outer name: error %v, want an encrypted client hello error", err)
	}
}

func TestCheckClientHelloRejectsNonTLS(t *testing.T) {
	hello := clientHello(t, "github.com")
	for name, data := range map[string][]byte{
		"plain HTTP": []byte("GET / HTTP/1.1\r\nHost: github.com\r\n\r\n"),
		"truncated":  hello[:len(hello)/2],
		"empty":      nil,
	} {
		if _, err := checkClientHello(bytes.NewReader(data), "github.com:443"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// handshakeThrough runs a TLS handshake for serverName through a tunnel to target.
func handshakeThrough(t *testing.T, proxy *httptest.Server, target, serverName string) error {
	t.Helper()
	conn, _ := connectTunnel(t, proxy, target)
	defer conn.Close()
	return tls.Client(conn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake()
}

// A tunnel to an allowed host must not reach another site on the same server.
func TestConnectServerName(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	ip := hostOf(upstream.URL)
	name := "localhost:" + strings.TrimPrefix(ip, "127.0.0.1:")
	allowPrivate := func(p *Proxy) { p.allowPrivate = true }

	for _, tc := range []struct {
		target, serverName string
		ok                 bool
	}{
		{name, "localhost", true},
		{name, "example.com", false},
		{name, "", false},
		{ip, "", true},
		{ip, "example.com", false},
	} {
		proxy, logs := startProxyWith(t, allowPrivate, name, ip)
		err := handshakeThrough(t, proxy, tc.target, tc.serverName)
		if tc.ok {
			if err != nil {
				t.Errorf("%s with server name %q: %v", tc.target, tc.serverName, err)
			}
			logs.waitForLog(t, "method=CONNECT", "decision=allow", "status=200")
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "access denied") {
			t.Errorf("%s with server name %q: got %v, want access denied", tc.target, tc.serverName, err)
		}
		logs.waitForLog(t, "method=CONNECT", "decision=deny", "status=200", "bytes_up=0", "error=\"tls server name")
	}
}

func TestConnectNonTLSDenied(t *testing.T) {
	received := make(chan []byte, 1)
	upstream := tcpServer(t, func(c net.Conn) {
		b, _ := io.ReadAll(c)
		received <- b
	})
	proxy, logs := startProxy(t, upstream)

	conn, r := connectTunnel(t, proxy, upstream)
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	got, _ := io.ReadAll(r)
	if !bytes.Equal(got, alertAccessDenied) {
		t.Errorf("client got %q, want an access_denied alert", got)
	}
	logs.waitForLog(t, "method=CONNECT", "decision=deny", "bytes_up=0", "error=\"no tls client hello")
	if b := <-received; len(b) != 0 {
		t.Errorf("server received %q", b)
	}
}

func TestConnectWithoutClientHelloTimesOut(t *testing.T) {
	upstream := tcpServer(t, func(net.Conn) {})
	proxy, logs := startProxyWith(t, func(p *Proxy) { p.helloTimeout = testIdleTimeout }, upstream)

	_, r := connectTunnel(t, proxy, upstream)
	start := time.Now()
	io.ReadAll(r)
	if waited := time.Since(start); waited < testIdleTimeout/2 || waited > 5*time.Second {
		t.Errorf("tunnel was closed after %s, want about %s", waited, testIdleTimeout)
	}
	logs.waitForLog(t, "method=CONNECT", "decision=deny", "error=\"no tls client hello")
}
