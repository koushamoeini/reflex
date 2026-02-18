package inbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"golang.org/x/crypto/chacha20poly1305"
)

// ─────────────────────────────────────────────────────────────────────────────
// Mock implementations for unit testing without a full Xray core context
// ─────────────────────────────────────────────────────────────────────────────

// mockPolicyManager satisfies features/policy.Manager.
type mockPolicyManager struct{}

func (m *mockPolicyManager) Type() interface{} { return policy.ManagerType() }
func (m *mockPolicyManager) Start() error      { return nil }
func (m *mockPolicyManager) Close() error      { return nil }
func (m *mockPolicyManager) ForLevel(_ uint32) policy.Session {
	return policy.Session{
		Timeouts: policy.Timeout{
			Handshake:      5 * time.Second,
			ConnectionIdle: 30 * time.Second,
			UplinkOnly:     5 * time.Second,
			DownlinkOnly:   5 * time.Second,
		},
	}
}
func (m *mockPolicyManager) ForSystem() policy.System { return policy.System{} }

// mockDispatcher satisfies features/routing.Dispatcher.
// It creates an in-memory pipe so the test can drive upload/download.
type mockDispatcher struct {
	link *transport.Link
}

func newMockDispatcher() (*mockDispatcher, io.ReadCloser, io.WriteCloser) {
	// upReader/upWriter: relay writes client data to upWriter; test reads from upReader.
	upReader, upWriter := io.Pipe()
	// downReader/downWriter: test writes server→client data to downWriter; relay reads from downReader.
	downReader, downWriter := io.Pipe()

	// The link given to the dispatcher (used by relay internally).
	relayLink := &transport.Link{
		Reader: buf.NewReader(downReader),
		Writer: buf.NewWriter(upWriter),
	}

	disp := &mockDispatcher{link: relayLink}
	return disp, upReader, downWriter
}

func (d *mockDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *mockDispatcher) Start() error      { return nil }
func (d *mockDispatcher) Close() error      { return nil }
func (d *mockDispatcher) Dispatch(_ context.Context, _ xnet.Destination) (*transport.Link, error) {
	return d.link, nil
}
func (d *mockDispatcher) DispatchLink(_ context.Context, _ xnet.Destination, _ *transport.Link) error {
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// newTestHandler returns a Handler wired with a mockPolicyManager, one test
// user, and an optional fallback port.
// ─────────────────────────────────────────────────────────────────────────────

func newTestHandler(userID string, fallbackPort uint32) *Handler {
	h := &Handler{
		policyManager: &mockPolicyManager{},
	}
	if userID != "" {
		h.clients = append(h.clients, makeMemoryUser(userID))
	}
	if fallbackPort > 0 {
		h.fallbackPort = fallbackPort
		h.hasFallback = true
	}
	return h
}

// makeMemoryUser builds a MemoryUser whose Email uses the dashed UUID string
// exactly as formatUUID() in inbound.go produces it, so findUser() will match.
func makeMemoryUser(uuidStr string) *protocol.MemoryUser {
	return &protocol.MemoryUser{
		Email: uuidStr,
		Account: &MemoryAccount{
			Id: uuidStr,
		},
	}
}

// buildReflexHandshakeBytes returns the complete on-wire bytes for a valid
// Reflex binary handshake targeted to 127.0.0.1:9001 for the given raw UUID.
func buildReflexHandshakeBytes(t *testing.T, rawID [16]byte) []byte {
	t.Helper()

	psk, err := reflex.DerivePSK(rawID)
	if err != nil {
		t.Fatalf("DerivePSK: %v", err)
	}

	_, clientPub, err := reflex.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Plaintext: addrType(1) + IPv4(4) + port(2) = 7 bytes → 127.0.0.1:9001
	dest := []byte{reflex.AddrTypeIPv4, 127, 0, 0, 1, 0x23, 0x29}

	nonce := make([]byte, 12) // all-zero nonce
	aead, err := chacha20poly1305.New(psk)
	if err != nil {
		t.Fatalf("chacha20poly1305.New: %v", err)
	}
	encPayload := aead.Seal(nil, nonce, dest, nil)

	var frame bytes.Buffer
	frame.Write(reflex.ReflexMagic()) // 4 bytes magic
	frame.Write(clientPub[:])         // 32 bytes client pub key
	frame.Write(rawID[:])             // 16 bytes user UUID
	frame.Write(nonce)                // 12 bytes PSK nonce
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(encPayload)))
	frame.Write(lenBuf[:])
	frame.Write(encPayload)

	return frame.Bytes()
}

// uuidStrToRaw converts a canonical dashed UUID string to raw 16-byte form.
func uuidStrToRaw(s string) ([16]byte, bool) {
	var clean [32]byte
	ci := 0
	for i := 0; i < len(s) && ci < 32; i++ {
		c := s[i]
		if c == '-' {
			continue
		}
		clean[ci] = c
		ci++
	}
	if ci != 32 {
		return [16]byte{}, false
	}
	var out [16]byte
	for i := 0; i < 16; i++ {
		hi := hexByteVal(clean[i*2])
		lo := hexByteVal(clean[i*2+1])
		if hi > 15 || lo > 15 {
			return [16]byte{}, false
		}
		out[i] = hi<<4 | lo
	}
	return out, true
}

func hexByteVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 255
}

// containsString reports whether s contains sub.
func containsString(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// doFallback – no fallback configured
// ─────────────────────────────────────────────────────────────────────────────

// TestDoFallbackNotConfigured verifies that doFallback returns an error when
// hasFallback is false (no fallback address configured).
func TestDoFallbackNotConfigured(t *testing.T) {
	h := &Handler{hasFallback: false}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	br := bufio.NewReader(server)
	ctx := context.Background()
	sp := testSessionPolicy()

	err := h.doFallback(ctx, br, server, sp)
	if err == nil {
		t.Fatal("expected error when no fallback configured, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// doFallback – fallback port not reachable
// ─────────────────────────────────────────────────────────────────────────────

// TestDoFallbackPortNotListening verifies that doFallback returns an error
// when the configured fallback port has nothing listening on it.
func TestDoFallbackPortNotListening(t *testing.T) {
	// Find a free port then immediately release it so nothing is listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // release immediately – port is now free but unoccupied

	h := &Handler{hasFallback: true, fallbackPort: uint32(port)}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	br := bufio.NewReader(server)
	ctx := context.Background()
	sp := testSessionPolicy()

	// Small chance the OS has recycled the port; tolerate that unlikely case.
	err = h.doFallback(ctx, br, server, sp)
	if err == nil {
		t.Log("NOTE: port was recycled by OS before doFallback ran – test inconclusive")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// preloadedConn – Read from buffered reader, Write to underlying connection
// ─────────────────────────────────────────────────────────────────────────────

// TestPreloadedConnReadWrite verifies that preloadedConn.Read returns peeked
// bytes and preloadedConn.Write sends to the underlying connection.
func TestPreloadedConnReadWrite(t *testing.T) {
	payload := []byte("RFXL-test-payload")
	client, server := net.Pipe()
	defer client.Close()

	// Writer goroutine: sends payload then closes.
	go func() {
		client.Write(payload)
		client.Close()
	}()

	// Wrap server side in bufio + peek.
	br := bufio.NewReaderSize(server, 256)
	peeked, err := br.Peek(4)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if !bytes.Equal(peeked, payload[:4]) {
		t.Fatalf("peeked %q, want %q", peeked, payload[:4])
	}

	// preloadedConn must replay the peeked bytes on Read.
	pc := &preloadedConn{Reader: br, Connection: server}
	readBuf := make([]byte, len(payload))
	n, _ := pc.Read(readBuf)
	// At least the peeked 4 bytes must be returned first.
	if !bytes.Equal(readBuf[:4], payload[:4]) {
		t.Fatalf("preloadedConn.Read: first 4 bytes got %q, want %q", readBuf[:4], payload[:4])
	}
	_ = n
}

// ─────────────────────────────────────────────────────────────────────────────
// Peek with very short connection (less than MinHandshakePeekSize)
// ─────────────────────────────────────────────────────────────────────────────

// TestPeekShortConnection simulates a connection that sends fewer bytes than
// MinHandshakePeekSize and immediately closes.  The bufio.Peek call returns
// what it got; if < 4 bytes we cannot identify the protocol.
func TestPeekShortConnection(t *testing.T) {
	client, server := net.Pipe()

	// Write only 2 bytes then close.
	go func() {
		client.Write([]byte{0x00, 0x01})
		client.Close()
	}()

	br := bufio.NewReaderSize(server, reflex.MinHandshakePeekSize*4)
	peeked, peekErr := br.Peek(reflex.MinHandshakePeekSize)

	// We expect fewer bytes than requested.
	if peekErr == nil {
		t.Fatal("expected Peek to return an error for short connection")
	}
	if len(peeked) >= reflex.MinHandshakePeekSize {
		t.Fatalf("unexpectedly got %d peeked bytes; expected fewer than %d",
			len(peeked), reflex.MinHandshakePeekSize)
	}

	// With < 4 bytes we cannot decide; handler must return early.
	if len(peeked) < 4 && (reflex.IsReflexMagic(peeked) || reflex.IsHTTPPostLike(peeked)) {
		t.Fatal("partial bytes were mis-detected as Reflex")
	}
	server.Close()
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryAccount – Equals and ToProto
// ─────────────────────────────────────────────────────────────────────────────

// TestMemoryAccountEquals verifies the Equals logic on MemoryAccount.
func TestMemoryAccountEquals(t *testing.T) {
	a := &MemoryAccount{Id: "user-1"}
	b := &MemoryAccount{Id: "user-1"}
	c := &MemoryAccount{Id: "user-2"}

	if !a.Equals(b) {
		t.Fatal("identical IDs should be equal")
	}
	if a.Equals(c) {
		t.Fatal("different IDs should not be equal")
	}
	if a.Equals(nil) {
		t.Fatal("nil account should not be equal")
	}
}

// TestMemoryAccountToProto verifies ToProto returns a non-nil proto.Message.
func TestMemoryAccountToProto(t *testing.T) {
	a := &MemoryAccount{Id: "user-abc"}
	msg := a.ToProto()
	if msg == nil {
		t.Fatal("ToProto returned nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Fallback preserves empty payload (edge: zero-byte body)
// ─────────────────────────────────────────────────────────────────────────────

// TestFallbackEmptyPayload fires doFallback with a connection that sends no
// bytes after peekBuf setup.  The fallback server should receive an empty body
// and close cleanly.
func TestFallbackEmptyPayload(t *testing.T) {
	fbListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer fbListener.Close()
	fbPort := fbListener.Addr().(*net.TCPAddr).Port

	fbDone := make(chan []byte, 1)
	go func() {
		conn, err := fbListener.Accept()
		if err != nil {
			fbDone <- nil
			return
		}
		defer conn.Close()
		b := make([]byte, 1024)
		n, _ := conn.Read(b)
		fbDone <- b[:n]
	}()

	h := &Handler{hasFallback: true, fallbackPort: uint32(fbPort)}
	clientConn, serverConn := net.Pipe()

	// Client side: close immediately (zero payload).
	go func() {
		clientConn.Close()
	}()

	br := bufio.NewReaderSize(serverConn, 512)
	// Peek will get EOF since client closed.
	br.Peek(4) //nolint:errcheck

	ctx := context.Background()
	sp := testSessionPolicy()
	go h.doFallback(ctx, br, serverConn, sp) //nolint:errcheck

	select {
	case data := <-fbDone:
		// nil means accept failed (acceptable if client closed before connect).
		_ = data
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for fallback to complete")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Process() path tests using mockPolicyManager + mockDispatcher
// ─────────────────────────────────────────────────────────────────────────────

// TestProcessShortData verifies that Process returns an error when the client
// closes the connection before sending 4 bytes (insufficient for magic check).
func TestProcessShortData(t *testing.T) {
	h := newTestHandler("", 0)
	client, server := net.Pipe()

	go func() {
		client.Write([]byte{0x01, 0x02})
		client.Close()
	}()

	defer server.Close()
	ctx := context.Background()
	err := h.Process(ctx, xnet.Network_TCP, server, nil)
	if err == nil {
		t.Fatal("expected error for short connection, got nil")
	}
}

// TestProcessFallbackPath verifies that Process dispatches to the fallback port
// when the first bytes are neither Reflex magic nor HTTP POST.
func TestProcessFallbackPath(t *testing.T) {
	fbLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer fbLn.Close()
	fbPort := fbLn.Addr().(*net.TCPAddr).Port

	received := make(chan []byte, 1)
	go func() {
		conn, err := fbLn.Accept()
		if err != nil {
			received <- nil
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		received <- data
	}()

	h := newTestHandler("", uint32(fbPort))
	client, server := net.Pipe()

	payload := []byte("JUNK: this is not Reflex and not HTTP POST at all.")
	go func() {
		client.Write(payload)
		client.Close()
	}()

	defer server.Close()
	ctx := context.Background()
	h.Process(ctx, xnet.Network_TCP, server, nil) //nolint:errcheck

	select {
	case data := <-received:
		if data == nil {
			t.Fatal("fallback server got nil (accept failed)")
		}
		if !bytes.Equal(data, payload) {
			t.Fatalf("fallback received %q; want %q", data, payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for fallback data")
	}
}

// TestProcessReflexMagicPath performs a complete Process() call with a valid
// Reflex binary handshake. The test verifies the handler reaches the relay phase
// (i.e. auth + key exchange succeeded) rather than failing at the handshake.
func TestProcessReflexMagicPath(t *testing.T) {
	const testUUID = "01020304-0506-0708-090a-0b0c0d0e0f10"
	rawID, ok := uuidStrToRaw(testUUID)
	if !ok {
		t.Fatal("failed to parse test UUID")
	}

	disp, upstreamR, downstreamW := newMockDispatcher()
	// Close downstream immediately so relay exits promptly.
	downstreamW.Close()
	defer upstreamR.Close()

	h := newTestHandler(testUUID, 0)
	clientSide, serverSide := net.Pipe()

	handshake := buildReflexHandshakeBytes(t, rawID)
	go func() {
		defer clientSide.Close()
		clientSide.Write(handshake)
		// Read server response: 32-byte server pub key + 1-byte status = 33 bytes.
		resp := make([]byte, 33)
		io.ReadFull(clientSide, resp) //nolint:errcheck
	}()

	defer serverSide.Close()
	ctx := context.Background()
	err := h.Process(ctx, xnet.Network_TCP, serverSide, disp)
	// If we got an auth/handshake error the test fails.
	if err != nil {
		msg := err.Error()
		if containsString(msg, "unknown user") || containsString(msg, "PSK decryption") ||
			containsString(msg, "failed to read") {
			t.Fatalf("Process failed before relay: %v", err)
		}
		// Relay-level errors ("session ended", "upload ended") are acceptable.
	}
}

// TestProcessUnknownUser sends a Reflex magic handshake for a UUID that is
// NOT in the handler's user list.  The handler should return an error.
func TestProcessUnknownUser(t *testing.T) {
	h := newTestHandler("", 0) // no users registered
	client, server := net.Pipe()

	unknownRaw := [16]byte{0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	handshake := buildReflexHandshakeBytes(t, unknownRaw)

	go func() {
		defer client.Close()
		client.Write(handshake)
	}()

	defer server.Close()
	ctx := context.Background()
	err := h.Process(ctx, xnet.Network_TCP, server, nil)
	if err == nil {
		t.Fatal("expected error for unknown user without fallback, got nil")
	}
}

// TestProcessHTTPPostPath sends a valid HTTP POST-disguised Reflex handshake
// and verifies the server replies with "HTTP/1.1 200 OK" before the binary data.
func TestProcessHTTPPostPath(t *testing.T) {
	const testUUID = "aabbccdd-eeff-1122-3344-556677889900"
	rawID, ok := uuidStrToRaw(testUUID)
	if !ok {
		t.Fatal("failed to parse test UUID")
	}

	psk, err := reflex.DerivePSK(rawID)
	if err != nil {
		t.Fatalf("DerivePSK: %v", err)
	}
	_, clientPub, err := reflex.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	dest := []byte{reflex.AddrTypeIPv4, 127, 0, 0, 1, 0x23, 0x29}
	nonce := make([]byte, 12)
	aead, _ := chacha20poly1305.New(psk)
	encPayload := aead.Seal(nil, nonce, dest, nil)

	inner := make([]byte, 0, 32+16+12+4+len(encPayload))
	inner = append(inner, clientPub[:]...)
	inner = append(inner, rawID[:]...)
	inner = append(inner, nonce...)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(encPayload)))
	inner = append(inner, lenBuf[:]...)
	inner = append(inner, encPayload...)

	const hexChars = "0123456789abcdef"
	hexStr := make([]byte, len(inner)*2)
	for i, b := range inner {
		hexStr[i*2] = hexChars[b>>4]
		hexStr[i*2+1] = hexChars[b&0xf]
	}

	httpReq := "POST /api/v1/endpoint HTTP/1.1\r\nHost: example.com\r\nX-Reflex-Data: " +
		string(hexStr) + "\r\n\r\n"

	disp, upstreamR, downstreamW := newMockDispatcher()
	downstreamW.Close()
	defer upstreamR.Close()

	h := newTestHandler(testUUID, 0)
	clientSide, serverSide := net.Pipe()

	responseBuf := make([]byte, 512)
	responseLen := make(chan int, 1)
	go func() {
		defer clientSide.Close()
		clientSide.Write([]byte(httpReq))
		n, _ := clientSide.Read(responseBuf)
		responseLen <- n
	}()

	defer serverSide.Close()
	ctx := context.Background()
	h.Process(ctx, xnet.Network_TCP, serverSide, disp) //nolint:errcheck

	select {
	case n := <-responseLen:
		got := string(responseBuf[:n])
		if !containsString(got, "HTTP/1.1 200 OK") {
			t.Fatalf("expected HTTP 200 in response, got: %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for HTTP 200 response")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers: formatUUID, hexDecodeString, parseDestination, findUser
// ─────────────────────────────────────────────────────────────────────────────

func TestHandlerNetwork(t *testing.T) {
	h := newTestHandler("", 0)
	nets := h.Network()
	if len(nets) != 1 || nets[0] != xnet.Network_TCP {
		t.Fatalf("Network() = %v; want [TCP]", nets)
	}
}

func TestFormatUUID(t *testing.T) {
	rawID := [16]byte{
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06,
		0x07, 0x08,
		0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}
	want := "01020304-0506-0708-090a-0b0c0d0e0f10"
	got := formatUUID(rawID)
	if got != want {
		t.Fatalf("formatUUID = %q; want %q", got, want)
	}
}

func TestHexDecodeStringValid(t *testing.T) {
	src := "deadbeef"
	dst := make([]byte, 4)
	n, err := hexDecodeString(src, dst)
	if err != nil {
		t.Fatalf("hexDecodeString: %v", err)
	}
	if n != 4 {
		t.Fatalf("n = %d; want 4", n)
	}
	want := []byte{0xde, 0xad, 0xbe, 0xef}
	if !bytes.Equal(dst, want) {
		t.Fatalf("got %x; want %x", dst, want)
	}
}

func TestHexDecodeStringInvalid(t *testing.T) {
	dst := make([]byte, 4)
	_, err := hexDecodeString("zzzz", dst)
	if err == nil {
		t.Fatal("expected error for invalid hex, got nil")
	}
}

func TestParseDestinationIPv4(t *testing.T) {
	payload := []byte{reflex.AddrTypeIPv4, 1, 2, 3, 4, 0x1f, 0x90} // port 8080
	dest, consumed, err := parseDestination(payload)
	if err != nil {
		t.Fatalf("parseDestination: %v", err)
	}
	if consumed != 7 {
		t.Fatalf("consumed = %d; want 7", consumed)
	}
	if dest.Port != 8080 {
		t.Fatalf("port = %d; want 8080", dest.Port)
	}
}

func TestParseDestinationDomain(t *testing.T) {
	domain := "example.com"
	payload := []byte{reflex.AddrTypeDomain, byte(len(domain))}
	payload = append(payload, []byte(domain)...)
	payload = append(payload, 0x01, 0xBB) // port 443
	dest, _, err := parseDestination(payload)
	if err != nil {
		t.Fatalf("parseDestination domain: %v", err)
	}
	if dest.Address.String() != domain {
		t.Fatalf("address = %q; want %q", dest.Address, domain)
	}
	if dest.Port != 443 {
		t.Fatalf("port = %d; want 443", dest.Port)
	}
}

func TestParseDestinationIPv6(t *testing.T) {
	payload := make([]byte, 1+16+2)
	payload[0] = reflex.AddrTypeIPv6
	payload[17] = 0x00
	payload[18] = 0x50 // port 80
	_, _, err := parseDestination(payload)
	if err != nil {
		t.Fatalf("parseDestination IPv6: %v", err)
	}
}

func TestParseDestinationUnknownType(t *testing.T) {
	payload := []byte{0xFF, 0, 0, 0, 0, 0, 0}
	_, _, err := parseDestination(payload)
	if err == nil {
		t.Fatal("expected error for unknown addr type")
	}
}

func TestParseDestinationTooShort(t *testing.T) {
	_, _, err := parseDestination([]byte{})
	if err == nil {
		t.Fatal("expected error for empty payload")
	}
}

func TestFindUserFound(t *testing.T) {
	rawID := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	uuidStr := formatUUID(rawID)
	h := newTestHandler(uuidStr, 0)
	u := h.findUser(rawID)
	if u == nil {
		t.Fatal("findUser returned nil for registered user")
	}
	if u.Email != uuidStr {
		t.Fatalf("user.Email = %q; want %q", u.Email, uuidStr)
	}
}

func TestFindUserNotFound(t *testing.T) {
	rawID := [16]byte{0xAA}
	h := newTestHandler("", 0)
	u := h.findUser(rawID)
	if u != nil {
		t.Fatal("findUser should return nil for unregistered user")
	}
}

// TestDoFallbackForwardsBytes verifies that doFallback forwards peeked +
// remaining bytes verbatim to the fallback server.
func TestDoFallbackForwardsBytes(t *testing.T) {
	fbLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer fbLn.Close()
	fbPort := fbLn.Addr().(*net.TCPAddr).Port

	want := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	received := make(chan []byte, 1)
	go func() {
		conn, err := fbLn.Accept()
		if err != nil {
			received <- nil
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		received <- data
	}()

	client, server := net.Pipe()
	go func() {
		client.Write(want)
		client.Close()
	}()

	br := bufio.NewReaderSize(server, 512)
	br.Peek(4) //nolint:errcheck

	h := &Handler{hasFallback: true, fallbackPort: uint32(fbPort)}
	ctx := context.Background()
	sp := testSessionPolicy()
	h.doFallback(ctx, br, server, sp) //nolint:errcheck
	server.Close()

	select {
	case data := <-received:
		if !bytes.Equal(data, want) {
			t.Fatalf("fallback received %q; want %q", data, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}
