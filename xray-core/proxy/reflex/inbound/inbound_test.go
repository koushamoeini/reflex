// Package inbound integration tests for Step 4: Fallback & protocol detection.
//
// These tests verify:
//  1. bufio.Peek does NOT consume bytes (fundamental correctness requirement)
//  2. isReflexMagic / isHTTPPostLike detection works correctly
//  3. Fallback forwards ALL bytes (including peeked ones) to the fallback server
//  4. Bytes are NOT lost when the bufio.Reader transitions from peek to read
package inbound

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/reflex"
)

// ---------------------------------------------------------------------------
// Helper: testSessionPolicy
// Returns a policy.Session with reasonable timeouts for unit tests.
// ---------------------------------------------------------------------------
func testSessionPolicy() policy.Session {
	return policy.Session{
		Timeouts: policy.Timeout{
			Handshake:      5 * time.Second,
			ConnectionIdle: 10 * time.Second,
			DownlinkOnly:   5 * time.Second,
			UplinkOnly:     5 * time.Second,
		},
	}
}

// ---------------------------------------------------------------------------
// 1. bufio.Peek does NOT consume bytes
// ---------------------------------------------------------------------------

// TestPeekPreservesBytes proves that bufio.Reader.Peek does not consume data.
// This is the core mechanism behind fallback byte-preservation: the server
// peeks at the first N bytes to determine the protocol, and if the connection
// must be forwarded, those bytes are still available for the fallback server.
func TestPeekPreservesBytes(t *testing.T) {
	original := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Write the full message from the "client" side.
	go func() {
		clientConn.Write(original)
		clientConn.Close()
	}()

	// Wrap the server side in a bufio.Reader and Peek the first 4 bytes.
	br := bufio.NewReaderSize(serverConn, 512)
	peeked, err := br.Peek(4)
	if err != nil {
		t.Fatalf("Peek(4): %v", err)
	}
	if string(peeked) != "GET " {
		t.Fatalf("Peek returned %q, want %q", peeked, "GET ")
	}

	// Read ALL bytes through the bufio.Reader.
	// The 4 peeked bytes MUST still be present at the start.
	got, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("after Peek, ReadAll returned %q, want full original %q", got, original)
	}
}

// TestPeekPreservesBytesLargeMessage verifies peek preservation for a payload
// larger than the peek size, matching the MinHandshakePeekSize scenario.
func TestPeekPreservesBytesLargeMessage(t *testing.T) {
	// Build a message longer than MinHandshakePeekSize.
	msg := make([]byte, reflex.MinHandshakePeekSize*4)
	for i := range msg {
		msg[i] = byte(i & 0xFF)
	}

	clientConn, serverConn := net.Pipe()

	go func() {
		clientConn.Write(msg)
		clientConn.Close()
	}()

	br := bufio.NewReaderSize(serverConn, reflex.MinHandshakePeekSize*8)
	peeked, err := br.Peek(reflex.MinHandshakePeekSize)
	if err != nil {
		t.Fatalf("Peek(%d): %v", reflex.MinHandshakePeekSize, err)
	}
	if len(peeked) != reflex.MinHandshakePeekSize {
		t.Fatalf("Peek returned %d bytes, want %d", len(peeked), reflex.MinHandshakePeekSize)
	}

	got, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != len(msg) {
		t.Fatalf("ReadAll: got %d bytes, want %d", len(got), len(msg))
	}
	for i := range msg {
		if got[i] != msg[i] {
			t.Fatalf("byte %d: got 0x%02x want 0x%02x", i, got[i], msg[i])
		}
	}
	serverConn.Close()
}

// ---------------------------------------------------------------------------
// 2. Protocol detection helpers (via exported reflex package functions)
// ---------------------------------------------------------------------------

// TestProtocolDetectionMagic confirms Reflex magic bytes are correctly detected.
func TestProtocolDetectionMagic(t *testing.T) {
	magic := reflex.ReflexMagic()
	// Add padding to reach MinHandshakePeekSize.
	padded := make([]byte, reflex.MinHandshakePeekSize)
	copy(padded, magic)

	if !reflex.IsReflexMagic(padded) {
		t.Fatal("IsReflexMagic: expected true for Reflex magic prefix, got false")
	}
	if !reflex.IsReflexHandshake(padded) {
		t.Fatal("IsReflexHandshake: expected true for Reflex magic, got false")
	}
}

// TestProtocolDetectionHTTPPost confirms an HTTP POST request is detected as a
// potential Reflex handshake (covert path).
func TestProtocolDetectionHTTPPost(t *testing.T) {
	req := []byte("POST /api/v1/endpoint HTTP/1.1\r\nHost: example.com\r\nX-Reflex-Data: deadbeef\r\n\r\n")
	padded := make([]byte, reflex.MinHandshakePeekSize)
	copy(padded, req)

	if !reflex.IsHTTPPostLike(padded) {
		t.Fatal("IsHTTPPostLike: expected true for HTTP POST, got false")
	}
	if !reflex.IsReflexHandshake(padded) {
		t.Fatal("IsReflexHandshake: expected true for HTTP POST, got false")
	}
}

// TestProtocolDetectionUnknown confirms non-Reflex traffic is NOT detected.
func TestProtocolDetectionUnknown(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
	}{
		{"TLS ClientHello", []byte{0x16, 0x03, 0x01, 0x00, 0xc8}},
		{"HTTP GET", []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")},
		{"SSH banner", []byte("SSH-2.0-OpenSSH_8.9\r\n")},
		{"raw binary", []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}},
	}
	for _, tc := range cases {
		padded := make([]byte, reflex.MinHandshakePeekSize)
		copy(padded, tc.input)
		if reflex.IsReflexHandshake(padded) {
			t.Errorf("%s: IsReflexHandshake unexpectedly returned true", tc.name)
		}
	}
}

// ---------------------------------------------------------------------------
// 3 & 4. Fallback: bytes preserved and forwarded to fallback server
// ---------------------------------------------------------------------------

// TestFallbackPreservesBytes is an end-to-end test that:
//
//  1. Starts a local TCP listener acting as the "fallback web server".
//  2. Creates a Handler with that port as the fallback destination.
//  3. Simulates an incoming connection that sends non-Reflex data.
//  4. Calls doFallback, verifying that:
//     a. The peeked bytes are among the bytes received by the fallback server.
//     b. Every byte sent by the simulated client arrives at the fallback server
//     (confirming byte-preservation through the bufio.Reader).
func TestFallbackPreservesBytes(t *testing.T) {
	// Build the non-Reflex payload (simulates a browser HTTP GET).
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestClient/1.0\r\n\r\n")

	// ------------------------------------------------------------------
	// Start the fallback server (echo-drain, collects all received bytes).
	// ------------------------------------------------------------------
	fbListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fallback listen: %v", err)
	}
	defer fbListener.Close()
	fbPort := fbListener.Addr().(*net.TCPAddr).Port

	fbReceived := make(chan []byte, 1)
	go func() {
		conn, err := fbListener.Accept()
		if err != nil {
			fbReceived <- nil
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		fbReceived <- data
	}()

	// ------------------------------------------------------------------
	// Build the inbound Handler with fallback configured.
	// ------------------------------------------------------------------
	h := &Handler{
		hasFallback:  true,
		fallbackPort: uint32(fbPort),
	}

	// ------------------------------------------------------------------
	// Simulate an incoming TCP connection using net.Pipe.
	// clientConn → we write the payload from "outside"
	// serverConn → this is what Handler sees as the incoming connection
	// ------------------------------------------------------------------
	clientConn, serverConn := net.Pipe()

	// Write payload from the client side, then close.
	go func() {
		clientConn.Write(payload)
		clientConn.Close()
	}()

	// Wrap the server side in a bufio.Reader and Peek (simulating Process).
	br := bufio.NewReaderSize(serverConn, 512)
	peeked, _ := br.Peek(4)
	// Confirm not-Reflex (GET != magic, != POST).
	if reflex.IsReflexHandshake(peeked) {
		t.Fatal("test setup error: GET request was mis-detected as Reflex")
	}

	// After peek, the bufio.Reader holds the first 4 bytes.
	// doFallback must forward them along with the rest of the payload.
	ctx := context.Background()
	sp := testSessionPolicy()

	fbDone := make(chan error, 1)
	go func() {
		fbDone <- h.doFallback(ctx, br, serverConn, sp)
	}()

	// Wait for the fallback server to receive data and the relay to finish.
	select {
	case received := <-fbReceived:
		if received == nil {
			t.Fatal("fallback server accept failed")
		}
		if string(received) != string(payload) {
			t.Fatalf("fallback received %q\nwant %q", received, payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for fallback server to receive data")
	}

	select {
	case err := <-fbDone:
		_ = err // io.EOF / connection closed is expected
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for doFallback to return")
	}

	serverConn.Close()
}

// TestFallbackPreservesLargePayload repeats the end-to-end fallback test with
// a payload larger than the bufio.Reader's buffer to verify streaming works.
func TestFallbackPreservesLargePayload(t *testing.T) {
	// 8 KB payload across multiple bufio buffer fills.
	payload := make([]byte, 8*1024)
	for i := range payload {
		payload[i] = byte(i & 0xFF)
	}

	fbListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fallback listen: %v", err)
	}
	defer fbListener.Close()
	fbPort := fbListener.Addr().(*net.TCPAddr).Port

	fbReceived := make(chan []byte, 1)
	go func() {
		conn, err := fbListener.Accept()
		if err != nil {
			fbReceived <- nil
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		fbReceived <- data
	}()

	h := &Handler{hasFallback: true, fallbackPort: uint32(fbPort)}

	clientConn, serverConn := net.Pipe()
	go func() {
		clientConn.Write(payload)
		clientConn.Close()
	}()

	br := bufio.NewReaderSize(serverConn, 512)
	br.Peek(4) // simulate protocol detection peek

	ctx := context.Background()
	sp := testSessionPolicy()

	fbDone := make(chan error, 1)
	go func() { fbDone <- h.doFallback(ctx, br, serverConn, sp) }()

	select {
	case received := <-fbReceived:
		if len(received) != len(payload) {
			t.Fatalf("fallback received %d bytes, want %d", len(received), len(payload))
		}
		for i := range payload {
			if received[i] != payload[i] {
				t.Fatalf("byte %d mismatch: got 0x%02x want 0x%02x", i, received[i], payload[i])
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	select {
	case <-fbDone:
	case <-time.After(5 * time.Second):
		t.Fatal("doFallback timeout")
	}
	serverConn.Close()
}
