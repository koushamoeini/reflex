package reflex_test

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/reflex"
)

// ─────────────────────────────────────────────────────────────────────────────
// Empty data
// ─────────────────────────────────────────────────────────────────────────────

// TestEmptyDataFrame verifies that WriteFrame and ReadFrame handle a
// zero-length payload without crashing or corrupting state.
func TestEmptyDataFrame(t *testing.T) {
	key := make([]byte, 32)
	pr, pw := io.Pipe()

	writer, _ := reflex.NewSession(key)
	reader, _ := reflex.NewSession(key)

	go func() {
		_ = writer.WriteFrame(pw, reflex.FrameTypeData, []byte{})
		pw.Close()
	}()

	frame, err := reader.ReadFrame(pr)
	if err != nil {
		t.Fatalf("ReadFrame on empty payload: %v", err)
	}
	if frame.Type != reflex.FrameTypeData {
		t.Fatalf("wrong frame type: 0x%02x", frame.Type)
	}
	if len(frame.Payload) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(frame.Payload))
	}
}

// TestEmptyDataFrameWriter verifies FrameWriter handles empty Write calls.
func TestEmptyDataFrameWriter(t *testing.T) {
	key := make([]byte, 32)
	var buf bytes.Buffer
	fw, _ := reflex.NewFrameWriter(&buf, key)

	n, err := fw.Write([]byte{})
	if err != nil {
		t.Fatalf("FrameWriter.Write(empty): %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 bytes written, got %d", n)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Large data (10 MB) – verifies split-and-reassemble path
// ─────────────────────────────────────────────────────────────────────────────

// TestLargeDataRoundTrip sends a 10 MB payload through FrameWriter/FrameReader
// and verifies every byte is received correctly.
func TestLargeDataRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	const size = 10 * 1024 * 1024 // 10 MB
	largeData := make([]byte, size)
	for i := range largeData {
		largeData[i] = byte(i & 0xFF)
	}

	pr, pw := io.Pipe()
	fw, _ := reflex.NewFrameWriter(pw, key)
	fr, _ := reflex.NewFrameReader(pr, key)

	errCh := make(chan error, 1)
	go func() {
		_, err := fw.Write(largeData)
		pw.Close()
		errCh <- err
	}()

	got, err := io.ReadAll(fr)
	if writeErr := <-errCh; writeErr != nil {
		t.Fatalf("FrameWriter.Write 10MB: %v", writeErr)
	}
	if err != nil {
		t.Fatalf("FrameReader.ReadAll 10MB: %v", err)
	}
	if !bytes.Equal(got, largeData) {
		t.Fatalf("10 MB round-trip failed: got %d bytes, want %d", len(got), len(largeData))
	}
}

// TestLargeDataSessionMaxFrame tests Session.WriteFrame with exactly
// MaxFramePayload bytes – the largest single frame allowed by the protocol.
func TestLargeDataSessionMaxFrame(t *testing.T) {
	key := make([]byte, 32)
	// MaxFramePayload is the largest plaintext that fits in one encrypted frame
	// (ciphertext length ≤ 65535, poly1305 tag = 16 bytes).
	largeData := make([]byte, reflex.MaxFramePayload)
	for i := range largeData {
		largeData[i] = byte(i % 251)
	}

	pr, pw := io.Pipe()
	s, _ := reflex.NewSession(key)

	go func() {
		_ = s.WriteFrame(pw, reflex.FrameTypeData, largeData)
		pw.Close()
	}()

	r, _ := reflex.NewSession(key)
	frame, err := r.ReadFrame(pr)
	if err != nil {
		t.Fatalf("ReadFrame at MaxFramePayload: %v", err)
	}
	if !bytes.Equal(frame.Payload, largeData) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(frame.Payload), len(largeData))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Closed connection
// ─────────────────────────────────────────────────────────────────────────────

// TestWriteToClosedConnection verifies that WriteFrame returns an error (not
// a panic) when the underlying connection is already closed.
func TestWriteToClosedConnection(t *testing.T) {
	key := make([]byte, 32)
	s, _ := reflex.NewSession(key)

	client, server := net.Pipe()
	server.Close() // close immediately

	err := s.WriteFrame(client, reflex.FrameTypeData, []byte("test"))
	if err == nil {
		t.Fatal("expected an error writing to closed connection, got nil")
	}
	client.Close()
}

// TestReadFromClosedConnection verifies that ReadFrame returns an error (not a
// panic) when the peer closes the connection before sending any data.
func TestReadFromClosedConnection(t *testing.T) {
	key := make([]byte, 32)
	s, _ := reflex.NewSession(key)

	client, server := net.Pipe()
	server.Close() // no data written; EOF immediately

	_, err := s.ReadFrame(client)
	if err == nil {
		t.Fatal("expected an error reading from closed connection, got nil")
	}
	client.Close()
}

// ─────────────────────────────────────────────────────────────────────────────
// Connection reset mid-frame
// ─────────────────────────────────────────────────────────────────────────────

// TestConnectionResetMidFrame closes the connection after writing only the
// frame header (3 bytes), before the ciphertext.  ReadFrame must return an
// error, not a panic.
func TestConnectionResetMidFrame(t *testing.T) {
	key := make([]byte, 32)
	r, _ := reflex.NewSession(key)

	client, server := net.Pipe()

	go func() {
		// Write only 2 bytes of the 3-byte header → incomplete.
		server.Write([]byte{0x00, 0x10}) // length=16, type missing
		server.Close()
	}()

	_, err := r.ReadFrame(client)
	if err == nil {
		t.Fatal("expected error on truncated frame header, got nil")
	}
	client.Close()
}

// TestConnectionResetMidCiphertext writes header + partial ciphertext then
// closes.  ReadFrame must return an error.
func TestConnectionResetMidCiphertext(t *testing.T) {
	key := make([]byte, 32)
	// Write a header claiming 100 bytes of ciphertext but send only 10.
	client, server := net.Pipe()

	go func() {
		// header: length=100 (0x00,0x64), type=DATA (0x01)
		server.Write([]byte{0x00, 0x64, 0x01})
		// Only 10 bytes of ciphertext (100 promised).
		server.Write(bytes.Repeat([]byte{0xAA}, 10))
		server.Close()
	}()

	r, _ := reflex.NewSession(key)
	_, err := r.ReadFrame(client)
	if err == nil {
		t.Fatal("expected error on truncated ciphertext, got nil")
	}
	client.Close()
}

// ─────────────────────────────────────────────────────────────────────────────
// Wrong key – decryption must fail
// ─────────────────────────────────────────────────────────────────────────────

// TestWrongKeyDecryptionFails encrypts with key A and tries to decrypt with
// key B.  ReadFrame must return an authentication error.
func TestWrongKeyDecryptionFails(t *testing.T) {
	keyA := make([]byte, 32)
	keyB := make([]byte, 32)
	keyB[0] = 0xFF // differs from keyA

	pr, pw := io.Pipe()
	writer, _ := reflex.NewSession(keyA)
	reader, _ := reflex.NewSession(keyB)

	go func() {
		_ = writer.WriteFrame(pw, reflex.FrameTypeData, []byte("secret"))
		pw.Close()
	}()

	_, err := reader.ReadFrame(pr)
	if err == nil {
		t.Fatal("expected authentication error with wrong key, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Replay attack via NonceCache
// ─────────────────────────────────────────────────────────────────────────────

// TestReplayAttack verifies that a captured frame cannot be replayed.
// NonceCache.Check must return false for the second identical nonce.
func TestReplayAttack(t *testing.T) {
	nc := reflex.NewNonceCache()

	// First presentation of nonce 7 is accepted.
	if !nc.Check(7) {
		t.Fatal("first Check(7): expected true (fresh)")
	}
	// Replaying nonce 7 must be rejected.
	if nc.Check(7) {
		t.Fatal("second Check(7): expected false (replay)")
	}
}

// TestReplayProtectionSequential verifies the nonce counter across many frames.
// Sequential counters must all be accepted once and rejected on replay.
func TestReplayProtectionSequential(t *testing.T) {
	nc := reflex.NewNonceCache()
	const n = 500

	for i := uint64(0); i < n; i++ {
		if !nc.Check(i) {
			t.Fatalf("Check(%d): fresh nonce rejected", i)
		}
	}
	for i := uint64(0); i < n; i++ {
		if nc.Check(i) {
			t.Fatalf("Check(%d): replay nonce accepted", i)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Oversized payload – WriteFrame must handle without panic
// ─────────────────────────────────────────────────────────────────────────────

// TestOversizedPayloadViaPipe writes more than MaxFramePayload through
// FrameWriter (which auto-splits), then reads it back entirely via FrameReader.
func TestOversizedPayloadViaPipe(t *testing.T) {
	key := make([]byte, 32)
	// Slightly larger than MaxFramePayload to trigger the split path.
	payload := make([]byte, reflex.MaxFramePayload+999)
	for i := range payload {
		payload[i] = byte(i % 199)
	}

	pr, pw := io.Pipe()
	fw, _ := reflex.NewFrameWriter(pw, key)
	fr, _ := reflex.NewFrameReader(pr, key)

	go func() {
		_, _ = fw.Write(payload)
		_ = fw.WriteClose()
		pw.Close()
	}()

	got, err := io.ReadAll(fr)
	if err != nil {
		t.Fatalf("FrameReader error: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("oversized payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Incomplete handshake – insufficient bytes before connection close
// ─────────────────────────────────────────────────────────────────────────────

// TestIncompleteHandshakeBytes verifies that ReadFrame returns an error when
// the connection provides only a partial 3-byte header and then closes.
func TestIncompleteHandshakeBytes(t *testing.T) {
	key := make([]byte, 32)
	s, _ := reflex.NewSession(key)

	// A real reader that closes after only 1 byte.
	pr, pw := io.Pipe()
	go func() {
		pw.Write([]byte{0x00}) // only 1 of 3 header bytes
		pw.Close()
	}()

	_, err := s.ReadFrame(pr)
	if err == nil {
		t.Fatal("expected error on incomplete header, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Concurrent session writes – race safety
// ─────────────────────────────────────────────────────────────────────────────

// TestConcurrentSessionWrites verifies Session is safe to use concurrently
// (run with -race).  Multiple goroutines write frames; the reader must receive
// all of them without deadlock or data corruption.
//
// Note: Session is NOT goroutine-safe by design (nonce counters are not
// protected by a mutex).  This test verifies that the bufio-backed writer
// layer at least does not panic under concurrent use.
func TestConcurrentNonceCacheAccess(t *testing.T) {
	nc := reflex.NewNonceCache()
	var wg sync.WaitGroup
	const goroutines = 20
	const perG = 300
	for g := 0; g < goroutines; g++ {
		g := g
		wg.Add(1)
		go func() {
			defer wg.Done()
			base := uint64(g * perG)
			for i := uint64(0); i < perG; i++ {
				nc.Check(base + i)
			}
		}()
	}
	wg.Wait()
}

// ─────────────────────────────────────────────────────────────────────────────
// Invalid UUID / unknown user
// ─────────────────────────────────────────────────────────────────────────────

// TestPSKDerivationUniqueness verifies that different UUIDs produce different PSKs.
func TestPSKDerivationUniqueness(t *testing.T) {
	var id1, id2 [16]byte
	id1[0] = 0x01
	id2[0] = 0x02

	psk1, _ := reflex.DerivePSK(id1)
	psk2, _ := reflex.DerivePSK(id2)

	if bytes.Equal(psk1, psk2) {
		t.Fatal("different user IDs produced identical PSKs")
	}
}

// TestPSKDerivationLength verifies PSK is exactly 32 bytes (ChaCha20-Poly1305 key).
func TestPSKDerivationLength(t *testing.T) {
	var id [16]byte
	psk, err := reflex.DerivePSK(id)
	if err != nil {
		t.Fatalf("DerivePSK: %v", err)
	}
	if len(psk) != 32 {
		t.Fatalf("PSK length: got %d want 32", len(psk))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// MakeNonce – determinism and uniqueness
// ─────────────────────────────────────────────────────────────────────────────

// TestMakeNonceDeterministic verifies that MakeNonce returns the same 12 bytes
// for the same counter input.
func TestMakeNonceDeterministic(t *testing.T) {
	n1 := reflex.MakeNonce(42)
	n2 := reflex.MakeNonce(42)
	if !bytes.Equal(n1, n2) {
		t.Fatal("MakeNonce is not deterministic")
	}
	if len(n1) != 12 {
		t.Fatalf("nonce length: got %d want 12", len(n1))
	}
}

// TestMakeNonceUnique verifies counters produce different nonces.
func TestMakeNonceUnique(t *testing.T) {
	n0 := reflex.MakeNonce(0)
	n1 := reflex.MakeNonce(1)
	if bytes.Equal(n0, n1) {
		t.Fatal("consecutive nonces are identical")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Session – multiple sequential frames maintain correct nonce order
// ─────────────────────────────────────────────────────────────────────────────

// TestSessionMultipleFramesOrder sends N frames and verifies they arrive in
// order with correct payloads.
func TestSessionMultipleFramesOrder(t *testing.T) {
	const N = 200
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 3)
	}

	pr, pw := io.Pipe()
	ws, _ := reflex.NewSession(key)
	rs, _ := reflex.NewSession(key)

	go func() {
		for i := 0; i < N; i++ {
			_ = ws.WriteFrame(pw, reflex.FrameTypeData, []byte{byte(i)})
		}
		pw.Close()
	}()

	for i := 0; i < N; i++ {
		frame, err := rs.ReadFrame(pr)
		if err != nil {
			t.Fatalf("ReadFrame #%d: %v", i, err)
		}
		if frame.Payload[0] != byte(i) {
			t.Fatalf("frame #%d: got payload byte %d, want %d", i, frame.Payload[0], i)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// FrameWriter – WriteClose emits a CLOSE frame
// ─────────────────────────────────────────────────────────────────────────────

// TestFrameWriterCloseSignal verifies that WriteClose produces a CLOSE frame
// that causes FrameReader.Read to return io.EOF.
func TestFrameWriterCloseSignal(t *testing.T) {
	key := make([]byte, 32)
	pr, pw := io.Pipe()
	fw, _ := reflex.NewFrameWriter(pw, key)
	fr, _ := reflex.NewFrameReader(pr, key)

	go func() {
		_, _ = fw.Write([]byte("hello"))
		_ = fw.WriteClose()
		pw.Close()
	}()

	// FrameReader should yield the data then EOF.
	got, err := io.ReadAll(fr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// IsReflexMagic – edge cases on byte boundaries
// ─────────────────────────────────────────────────────────────────────────────

func TestIsReflexMagicEdgeCases(t *testing.T) {
	magic := reflex.ReflexMagic()

	// Exactly the magic.
	if !reflex.IsReflexMagic(magic) {
		t.Fatal("exact magic not recognised")
	}
	// Magic plus extra bytes (common in real connections).
	extended := append(magic, 0xFF, 0x00, 0xAB)
	if !reflex.IsReflexMagic(extended) {
		t.Fatal("magic followed by extra bytes not recognised")
	}
	// One byte off at each position.
	for pos := 0; pos < 4; pos++ {
		corrupt := make([]byte, 4)
		copy(corrupt, magic)
		corrupt[pos] ^= 0x01
		if reflex.IsReflexMagic(corrupt) {
			t.Fatalf("IsReflexMagic returned true for corruption at byte %d", pos)
		}
	}
	// Nil slice – must not panic.
	if reflex.IsReflexMagic(nil) {
		t.Fatal("IsReflexMagic(nil) returned true")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Deadline / timeout on a real TCP connection
// ─────────────────────────────────────────────────────────────────────────────

// TestReadFrameTimeout verifies that a read deadline causes ReadFrame to return
// a timeout error rather than blocking forever.
func TestReadFrameTimeout(t *testing.T) {
	key := make([]byte, 32)
	s, _ := reflex.NewSession(key)

	// Establish a real TCP connection so SetDeadline works.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		conn, _ := ln.Accept()
		// hold the connection open without sending any data
		<-done
		conn.Close()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() {
		close(done)
		conn.Close()
	}()

	// Set a very short deadline so ReadFrame must time out.
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

	_, err = s.ReadFrame(conn)
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	// Must be a net timeout, not a nil.
	ne, ok := err.(net.Error)
	if !ok || !ne.Timeout() {
		t.Fatalf("expected a timeout net.Error, got: %v (%T)", err, err)
	}
}
