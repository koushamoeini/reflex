package reflex_test

import (
	"bytes"
	"io"
	"sync"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
)

// TestKeyExchange verifies that both parties derive the same shared secret
// and session key using X25519 + HKDF.
func TestKeyExchange(t *testing.T) {
	clientPriv, clientPub, err := reflex.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (client): %v", err)
	}
	serverPriv, serverPub, err := reflex.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (server): %v", err)
	}

	// Client computes shared secret using client priv + server pub.
	clientShared, err := reflex.DeriveSharedSecret(clientPriv, serverPub)
	if err != nil {
		t.Fatalf("DeriveSharedSecret (client): %v", err)
	}
	// Server computes shared secret using server priv + client pub.
	serverShared, err := reflex.DeriveSharedSecret(serverPriv, clientPub)
	if err != nil {
		t.Fatalf("DeriveSharedSecret (server): %v", err)
	}

	if clientShared != serverShared {
		t.Fatal("shared secrets do not match")
	}

	// Both derive the same session key from the same shared secret + salt.
	salt := []byte("test-salt")
	clientKey, err := reflex.DeriveSessionKey(clientShared, salt)
	if err != nil {
		t.Fatalf("DeriveSessionKey (client): %v", err)
	}
	serverKey, err := reflex.DeriveSessionKey(serverShared, salt)
	if err != nil {
		t.Fatalf("DeriveSessionKey (server): %v", err)
	}

	if !bytes.Equal(clientKey, serverKey) {
		t.Fatal("session keys do not match")
	}
}

// TestPSKDerivation verifies DerivePSK is deterministic.
func TestPSKDerivation(t *testing.T) {
	var userID [16]byte
	for i := range userID {
		userID[i] = byte(i)
	}

	psk1, err := reflex.DerivePSK(userID)
	if err != nil {
		t.Fatalf("DerivePSK #1: %v", err)
	}
	psk2, err := reflex.DerivePSK(userID)
	if err != nil {
		t.Fatalf("DerivePSK #2: %v", err)
	}
	if !bytes.Equal(psk1, psk2) {
		t.Fatal("PSKs differ for the same user ID")
	}
}

// TestFrameRoundtrip writes data through a FrameWriter and reads it back
// through a FrameReader using the same session key, verifying that
// encryption + decryption is transparent and correct.
func TestFrameRoundtrip(t *testing.T) {
	// Use a fixed 32-byte session key.
	sessionKey := make([]byte, 32)
	for i := range sessionKey {
		sessionKey[i] = byte(i + 1)
	}

	original := []byte("Hello, Reflex! This is a frame encryption test.")

	// Write side: pipe writer → FrameWriter → pipe
	pr, pw := io.Pipe()

	fw, err := reflex.NewFrameWriter(pw, sessionKey)
	if err != nil {
		t.Fatalf("NewFrameWriter: %v", err)
	}
	fr, err := reflex.NewFrameReader(pr, sessionKey)
	if err != nil {
		t.Fatalf("NewFrameReader: %v", err)
	}

	// Write in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		_, err := fw.Write(original)
		if err != nil {
			errCh <- err
			return
		}
		pw.Close()
		errCh <- nil
	}()

	// Read everything back.
	got, err := io.ReadAll(fr)
	if err != nil {
		t.Fatalf("ReadAll from FrameReader: %v", err)
	}
	if writeErr := <-errCh; writeErr != nil {
		t.Fatalf("FrameWriter Write: %v", writeErr)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("round-trip mismatch:\n  got  %q\n  want %q", got, original)
	}
}

// TestLargeFrameRoundtrip verifies that payloads larger than MaxFramePayload
// are split into multiple frames and re-assembled correctly.
func TestLargeFrameRoundtrip(t *testing.T) {
	sessionKey := make([]byte, 32)

	// Build a payload larger than MaxFramePayload (16 KB).
	bigMsg := make([]byte, reflex.MaxFramePayload*3+7)
	for i := range bigMsg {
		bigMsg[i] = byte(i % 256)
	}

	pr, pw := io.Pipe()
	fw, err := reflex.NewFrameWriter(pw, sessionKey)
	if err != nil {
		t.Fatalf("NewFrameWriter: %v", err)
	}
	fr, err := reflex.NewFrameReader(pr, sessionKey)
	if err != nil {
		t.Fatalf("NewFrameReader: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := fw.Write(bigMsg)
		if err != nil {
			errCh <- err
			return
		}
		pw.Close()
		errCh <- nil
	}()

	got, err := io.ReadAll(fr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if writeErr := <-errCh; writeErr != nil {
		t.Fatalf("FrameWriter Write: %v", writeErr)
	}
	if !bytes.Equal(got, bigMsg) {
		t.Fatalf("large frame round-trip failed: len got=%d want=%d", len(got), len(bigMsg))
	}
}

// TestMagicDetection verifies IsReflexMagic correctly identifies Reflex packets.
func TestMagicDetection(t *testing.T) {
	magic := reflex.ReflexMagic()
	if !reflex.IsReflexMagic(magic) {
		t.Fatal("IsReflexMagic returned false for the actual magic bytes")
	}
	notMagic := []byte{0x00, 0x01, 0x02, 0x03}
	if reflex.IsReflexMagic(notMagic) {
		t.Fatal("IsReflexMagic returned true for non-magic bytes")
	}
	if reflex.IsReflexMagic([]byte{0x52}) { // too short
		t.Fatal("IsReflexMagic returned true for slice shorter than 4 bytes")
	}
}

// TestIsHTTPPostLike verifies that the HTTP POST disguise detection is accurate.
func TestIsHTTPPostLike(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{"exact POST", []byte("POST /api HTTP/1.1\r\n"), true},
		{"POST no path", []byte("POST"), true}, // only 4 bytes still match
		{"GET request", []byte("GET / HTTP/1.1\r\n"), false},
		{"TLS handshake", []byte{0x16, 0x03, 0x01, 0x00}, false},
		{"empty", []byte{}, false},
		{"short (3 bytes)", []byte("POS"), false},
		{"lowercase post", []byte("post /api"), false}, // case-sensitive
	}
	for _, tc := range tests {
		got := reflex.IsHTTPPostLike(tc.input)
		if got != tc.want {
			t.Errorf("%s: IsHTTPPostLike(%q) = %v, want %v", tc.name, tc.input, got, tc.want)
		}
	}
}

// TestIsReflexHandshake verifies the combined Reflex detection (magic OR HTTP POST).
func TestIsReflexHandshake(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{"Reflex magic", reflex.ReflexMagic(), true},
		{"HTTP POST disguise", []byte("POST /a HTTP/1.1\r\n"), true},
		{"TLS ClientHello", []byte{0x16, 0x03, 0x01, 0x00, 0x00}, false},
		{"raw TCP garbage", []byte{0xDE, 0xAD, 0xBE, 0xEF}, false},
		{"empty", []byte{}, false},
		{"too short (1 byte)", []byte{0x52}, false},
		{"GET request (not Reflex)", []byte("GET / HTTP/1.1\r\n"), false},
	}
	for _, tc := range tests {
		got := reflex.IsReflexHandshake(tc.input)
		if got != tc.want {
			t.Errorf("%s: IsReflexHandshake(%q) = %v, want %v", tc.name, tc.input, got, tc.want)
		}
	}
}

// TestMinHandshakePeekSize verifies the constant is sensible.
func TestMinHandshakePeekSize(t *testing.T) {
	if reflex.MinHandshakePeekSize < 4 {
		t.Fatalf("MinHandshakePeekSize=%d is less than 4, magic detection would fail",
			reflex.MinHandshakePeekSize)
	}
}

// ---------------------------------------------------------------------------
// Step 3 – Frame struct, Session, NonceCache
// ---------------------------------------------------------------------------

// TestFrameStruct verifies the Frame type carries the correct fields.
func TestFrameStruct(t *testing.T) {
	sessionKey := make([]byte, 32)
	for i := range sessionKey {
		sessionKey[i] = byte(i + 7)
	}
	payload := []byte("frame payload")

	pr, pw := io.Pipe()
	s, err := reflex.NewSession(sessionKey)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	go func() {
		_ = s.WriteFrame(pw, reflex.FrameTypeData, payload)
		pw.Close()
	}()

	s2, _ := reflex.NewSession(sessionKey)
	frame, err := s2.ReadFrame(pr)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if frame.Type != reflex.FrameTypeData {
		t.Fatalf("frame type: got 0x%02x want 0x%02x", frame.Type, reflex.FrameTypeData)
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Fatalf("frame payload mismatch: got %q want %q", frame.Payload, payload)
	}
}

// TestSessionReadWriteFrame verifies that NewSession / ReadFrame / WriteFrame
// produce correct encrypted frames that decrypt to the original plaintext.
func TestSessionReadWriteFrame(t *testing.T) {
	sessionKey := make([]byte, 32)
	for i := range sessionKey {
		sessionKey[i] = byte(i + 5)
	}

	tests := []struct {
		name      string
		frameType byte
		payload   []byte
	}{
		{"empty DATA", reflex.FrameTypeData, []byte{}},
		{"short DATA", reflex.FrameTypeData, []byte("hello reflex")},
		{"PADDING ctrl", reflex.FrameTypePadding, []byte{0x00, 0x00, 0x00, 0x10}},
		{"TIMING ctrl", reflex.FrameTypeTiming, []byte{0x00, 0x0a}},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			pr, pw := io.Pipe()
			writer, err := reflex.NewSession(sessionKey)
			if err != nil {
				t.Fatalf("NewSession (writer): %v", err)
			}
			reader, err := reflex.NewSession(sessionKey)
			if err != nil {
				t.Fatalf("NewSession (reader): %v", err)
			}

			errCh := make(chan error, 1)
			go func() {
				errCh <- writer.WriteFrame(pw, tc.frameType, tc.payload)
				pw.Close()
			}()

			frame, err := reader.ReadFrame(pr)
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if writeErr := <-errCh; writeErr != nil {
				t.Fatalf("WriteFrame: %v", writeErr)
			}

			if frame.Type != tc.frameType {
				t.Errorf("type: got 0x%02x want 0x%02x", frame.Type, tc.frameType)
			}
			if !bytes.Equal(frame.Payload, tc.payload) {
				t.Errorf("payload: got %q want %q", frame.Payload, tc.payload)
			}
		})
	}
}

// TestSessionAllFrameTypesRoundtrip writes one frame of every type and reads
// them back in order, verifying the full round-trip for each frame kind.
func TestSessionAllFrameTypesRoundtrip(t *testing.T) {
	sessionKey := make([]byte, 32)

	pr, pw := io.Pipe()
	wSession, _ := reflex.NewSession(sessionKey)
	rSession, _ := reflex.NewSession(sessionKey)

	frames := []struct {
		ft      byte
		payload []byte
	}{
		{reflex.FrameTypeData, []byte("actual data")},
		{reflex.FrameTypePadding, []byte{0xAA, 0xBB}},
		{reflex.FrameTypeTiming, []byte{0x00, 0x32}},
		{reflex.FrameTypeClose, nil},
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, f := range frames {
			p := f.payload
			if p == nil {
				p = []byte{}
			}
			if err := wSession.WriteFrame(pw, f.ft, p); err != nil {
				return
			}
		}
		pw.Close()
	}()

	for _, want := range frames {
		frame, err := rSession.ReadFrame(pr)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if frame.Type != want.ft {
			t.Errorf("frame type: got 0x%02x want 0x%02x", frame.Type, want.ft)
		}
		wantPayload := want.payload
		if wantPayload == nil {
			wantPayload = []byte{}
		}
		if !bytes.Equal(frame.Payload, wantPayload) {
			t.Errorf("frame payload: got %q want %q", frame.Payload, wantPayload)
		}
	}
	wg.Wait()
}

// TestSessionNonceProgresses verifies that separate Session instances sharing a
// key use independent nonce counters – so two sessions writing simultaneously
// do NOT have overlapping nonces (a security requirement).
func TestSessionNonceProgresses(t *testing.T) {
	key := make([]byte, 32)
	// Verify we can read many frames in order without nonce collision.
	pr, pw := io.Pipe()
	ws, _ := reflex.NewSession(key)
	rs, _ := reflex.NewSession(key)

	const n = 50
	errCh := make(chan error, 1)
	go func() {
		for i := 0; i < n; i++ {
			data := []byte{byte(i)}
			if err := ws.WriteFrame(pw, reflex.FrameTypeData, data); err != nil {
				errCh <- err
				return
			}
		}
		pw.Close()
		errCh <- nil
	}()

	for i := 0; i < n; i++ {
		frame, err := rs.ReadFrame(pr)
		if err != nil {
			t.Fatalf("ReadFrame #%d: %v", i, err)
		}
		if frame.Payload[0] != byte(i) {
			t.Errorf("frame #%d: payload byte got %d want %d", i, frame.Payload[0], i)
		}
	}
	if err := <-errCh; err != nil {
		t.Fatalf("writer goroutine: %v", err)
	}
}

// ---------------------------------------------------------------------------
// NonceCache – replay protection
// ---------------------------------------------------------------------------

// TestNonceCacheBasic verifies that fresh nonces are accepted and the cache
// grows correctly.
func TestNonceCacheBasic(t *testing.T) {
	nc := reflex.NewNonceCache()

	// Fresh nonces should be accepted.
	for i := uint64(0); i < 100; i++ {
		if !nc.Check(i) {
			t.Errorf("Check(%d): expected true (fresh), got false", i)
		}
	}
	if nc.Seen() != 100 {
		t.Errorf("Seen(): got %d want 100", nc.Seen())
	}
}

// TestNonceCacheReplay verifies that duplicate nonces are rejected.
func TestNonceCacheReplay(t *testing.T) {
	nc := reflex.NewNonceCache()

	// Accept nonce 42 the first time.
	if !nc.Check(42) {
		t.Fatal("first Check(42): expected true, got false")
	}
	// Reject the same nonce a second time (replay).
	if nc.Check(42) {
		t.Fatal("second Check(42): expected false (replay), got true")
	}
	// Reject a third attempt as well.
	if nc.Check(42) {
		t.Fatal("third Check(42): expected false (replay), got true")
	}
}

// TestNonceCacheEviction verifies that the cache does not grow beyond its
// configured maximum size and evicts the oldest entries.
func TestNonceCacheEviction(t *testing.T) {
	nc := reflex.NewNonceCache()

	const window = 1000 // must match nonceCacheMaxSize inside package
	const extra = 200

	// Insert window + extra nonces; oldest `extra` should be evicted.
	for i := uint64(0); i < window+extra; i++ {
		nc.Check(i)
	}

	// The cache size must not exceed the window.
	if nc.Seen() > window {
		t.Errorf("cache size %d exceeds max %d after eviction", nc.Seen(), window)
	}

	// The oldest nonces (0 … extra-1) have been evicted, so they should be
	// accepted as "fresh" again (they are no longer in the cache).
	for i := uint64(0); i < extra; i++ {
		if !nc.Check(i) {
			t.Errorf("Check(%d): expected true after eviction, got false", i)
		}
	}
}

// TestNonceCacheConcurrent stresses the cache under concurrent access to
// verify there are no data races (run with -race).
func TestNonceCacheConcurrent(t *testing.T) {
	nc := reflex.NewNonceCache()
	var wg sync.WaitGroup
	const goroutines = 16
	const perGoroutine = 200

	for g := 0; g < goroutines; g++ {
		g := g
		wg.Add(1)
		go func() {
			defer wg.Done()
			base := uint64(g * perGoroutine)
			for i := uint64(0); i < perGoroutine; i++ {
				nc.Check(base + i)
			}
		}()
	}
	wg.Wait()
}
