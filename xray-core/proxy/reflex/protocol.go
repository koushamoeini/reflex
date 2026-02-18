package reflex

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Protocol constants
const (
	// ReflexMagicBytes is the 4-byte magic prefix for Reflex connections.
	// ASCII "RFXL"
	ReflexMagicByte0 = byte(0x52) // 'R'
	ReflexMagicByte1 = byte(0x46) // 'F'
	ReflexMagicByte2 = byte(0x58) // 'X'
	ReflexMagicByte3 = byte(0x4C) // 'L'

	// Frame types (1 byte in each frame header)
	FrameTypeData    = byte(0x01) // DATA: real user payload
	FrameTypePadding = byte(0x02) // PADDING_CTRL: padding control
	FrameTypeTiming  = byte(0x03) // TIMING_CTRL: timing control
	FrameTypeClose   = byte(0x04) // CLOSE: connection close signal

	// Address type bytes inside the encrypted handshake payload
	AddrTypeIPv4   = byte(0x01)
	AddrTypeDomain = byte(0x02)
	AddrTypeIPv6   = byte(0x03)

	// MaxFramePayload is the maximum plaintext bytes per DATA frame.
	// 16 KB matches TLS record size, minimising metadata leakage.
	MaxFramePayload = 16 * 1024

	// HandshakeMinSize is the minimum number of bytes we need before we can
	// decide whether this is a Reflex connection or a fallback one.
	// magic(4) + clientPubKey(32) + userID(16) = 52 bytes minimum.
	HandshakeMinSize = 52
)

// ReflexMagic returns the 4-byte magic prefix as a slice.
func ReflexMagic() []byte {
	return []byte{ReflexMagicByte0, ReflexMagicByte1, ReflexMagicByte2, ReflexMagicByte3}
}

// IsReflexMagic returns true if the first 4 bytes of buf are the Reflex magic.
func IsReflexMagic(buf []byte) bool {
	return len(buf) >= 4 &&
		buf[0] == ReflexMagicByte0 &&
		buf[1] == ReflexMagicByte1 &&
		buf[2] == ReflexMagicByte2 &&
		buf[3] == ReflexMagicByte3
}

// IsHTTPPostLike returns true if the first bytes look like the start of an
// HTTP POST request.  Reflex clients can disguise the handshake as a POST.
func IsHTTPPostLike(peeked []byte) bool {
	return len(peeked) >= 4 &&
		peeked[0] == 'P' &&
		peeked[1] == 'O' &&
		peeked[2] == 'S' &&
		peeked[3] == 'T'
}

// IsReflexHandshake returns true if the peeked bytes indicate a Reflex
// connection – either via the binary magic prefix (fast path, lower overhead)
// or via the HTTP POST disguise (slower parse, more covert).
func IsReflexHandshake(peeked []byte) bool {
	return IsReflexMagic(peeked) || IsHTTPPostLike(peeked)
}

// MinHandshakePeekSize is the minimum number of bytes to peek from an
// incoming connection before deciding whether it is a Reflex session.
// 64 bytes covers the magic (4 B) and the start of an HTTP request line.
const MinHandshakePeekSize = 64

// -------------------------------------------------------------------
// Key generation and derivation
// -------------------------------------------------------------------

// GenerateKeyPair generates a fresh X25519 key pair.
func GenerateKeyPair() (privateKey [32]byte, publicKey [32]byte, err error) {
	if _, err = io.ReadFull(rand.Reader, privateKey[:]); err != nil {
		return
	}
	// RFC 7748 clamping
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	pub, e := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if e != nil {
		err = e
		return
	}
	copy(publicKey[:], pub)
	return
}

// DeriveSharedSecret computes the X25519 shared secret from our private key and
// the remote party's public key.
func DeriveSharedSecret(privateKey, peerPublicKey [32]byte) ([32]byte, error) {
	result, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return [32]byte{}, err
	}
	var shared [32]byte
	copy(shared[:], result)
	return shared, nil
}

// DeriveSessionKey derives a 32-byte ChaCha20-Poly1305 key from the X25519
// shared secret via HKDF-SHA256.
//
// salt should be unique per session (e.g., concatenation of nonces).
func DeriveSessionKey(sharedSecret [32]byte, salt []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, sharedSecret[:], salt, []byte("reflex-session-v1"))
	key := make([]byte, chacha20poly1305.KeySize)
	_, err := io.ReadFull(r, key)
	return key, err
}

// DerivePSK derives the Pre-Shared Key for a given user UUID.
// The PSK protects the encrypted destination payload inside the initial
// client handshake packet.
func DerivePSK(userID [16]byte) ([]byte, error) {
	r := hkdf.New(sha256.New, userID[:], nil, []byte("reflex-psk-v1"))
	key := make([]byte, chacha20poly1305.KeySize)
	_, err := io.ReadFull(r, key)
	return key, err
}

// MakeNonce builds a 12-byte AEAD nonce from an 8-byte counter.
// Bytes 0-3 are zero, bytes 4-11 are the counter in big-endian.
func MakeNonce(counter uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize) // 12 bytes
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// -------------------------------------------------------------------
// Frame struct
// -------------------------------------------------------------------

// Frame is the decoded, plaintext representation of one Reflex wire frame.
//
// Wire:  [length: 2 B big-endian][type: 1 B][ciphertext: length B]
// After decryption the Payload field holds the raw plaintext bytes.
type Frame struct {
	Length  uint16
	Type    byte
	Payload []byte
}

// -------------------------------------------------------------------
// Session – stateful frame read/write with per-direction nonce counters
// -------------------------------------------------------------------

// Session provides a frame-level API over a ChaCha20-Poly1305 AEAD.
// It maintains independent read and write nonce counters so that
// both directions of a connection are independently protected.
//
// Usage:
//
//	s, _ := NewSession(sessionKey)
//	_ = s.WriteFrame(conn, FrameTypeData, payload)
//	frame, _ := s.ReadFrame(conn)
type Session struct {
	key        []byte
	aead       cipher.AEAD
	readNonce  uint64
	writeNonce uint64
}

// NewSession creates a Session from a 32-byte ChaCha20-Poly1305 session key.
func NewSession(sessionKey []byte) (*Session, error) {
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}
	return &Session{
		key:  sessionKey,
		aead: aead,
	}, nil
}

// ReadFrame reads exactly one frame from r, decrypts it, and returns the
// decoded Frame.  Control frames (PADDING, TIMING) are returned as-is so
// the caller can decide whether to skip or honour them.
func (s *Session) ReadFrame(r io.Reader) (*Frame, error) {
	// 3-byte header: [length(2)][type(1)]
	header := make([]byte, 3)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(header[0:2])
	frameType := header[2]

	// Read ciphertext.
	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(r, ciphertext); err != nil {
		return nil, err
	}

	// Decrypt with the current read nonce.
	nonce := MakeNonce(s.readNonce)
	s.readNonce++
	plaintext, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return &Frame{
		Length:  length,
		Type:    frameType,
		Payload: plaintext,
	}, nil
}

// WriteFrame encrypts data and writes a single frame of the given type to w.
func (s *Session) WriteFrame(w io.Writer, frameType byte, data []byte) error {
	nonce := MakeNonce(s.writeNonce)
	s.writeNonce++
	encrypted := s.aead.Seal(nil, nonce, data, nil)

	header := [3]byte{}
	binary.BigEndian.PutUint16(header[0:2], uint16(len(encrypted)))
	header[2] = frameType

	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(encrypted)
	return err
}

// -------------------------------------------------------------------
// NonceCache – replay-attack protection
// -------------------------------------------------------------------

// nonceCacheMaxSize is the maximum number of nonces kept in the cache.
// Entries older than this window are evicted.
const nonceCacheMaxSize = 1000

// NonceCache records the most-recently seen nonces and rejects duplicates.
// It is safe for concurrent use.
//
// For the sequential counter-nonce scheme used inside a single session the
// cache mostly acts as a safeguard against:
//   - mis-handled retransmits
//   - an attacker resending a captured frame
type NonceCache struct {
	mu      sync.Mutex
	seen    map[uint64]struct{} // set of nonce values
	ordered []uint64            // insertion-order slice for eviction
}

// NewNonceCache returns an empty, ready-to-use NonceCache.
func NewNonceCache() *NonceCache {
	return &NonceCache{
		seen:    make(map[uint64]struct{}),
		ordered: make([]uint64, 0, nonceCacheMaxSize+1),
	}
}

// Check reports whether nonce is fresh (not previously seen) and records it.
// Returns true  → nonce is fresh, the packet should be processed.
// Returns false → nonce is a replay, the packet should be dropped.
func (nc *NonceCache) Check(nonce uint64) bool {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	if _, dup := nc.seen[nonce]; dup {
		return false // replay detected
	}

	nc.seen[nonce] = struct{}{}
	nc.ordered = append(nc.ordered, nonce)

	// Evict the oldest entry when we exceed the window.
	if len(nc.ordered) > nonceCacheMaxSize {
		evict := nc.ordered[0]
		nc.ordered = nc.ordered[1:]
		delete(nc.seen, evict)
	}

	return true
}

// Seen returns the current number of nonces held in the cache.
func (nc *NonceCache) Seen() int {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	return len(nc.seen)
}

// -------------------------------------------------------------------
// Frame I/O  (streaming io.Reader / io.Writer wrappers)
// -------------------------------------------------------------------

// FrameWriter encrypts outgoing data into Reflex frames and writes them to
// the underlying io.Writer.
//
// Frame wire format:
//
//	[length: 2 bytes big-endian]  – length of the ciphertext below
//	[type:   1 byte]              – FrameType* constants
//	[ciphertext: length bytes]    – ChaCha20-Poly1305 ciphertext (includes 16-byte tag)
type FrameWriter struct {
	w       io.Writer
	aead    cipher.AEAD
	counter uint64
}

// NewFrameWriter creates a FrameWriter that encrypts frames with sessionKey.
func NewFrameWriter(w io.Writer, sessionKey []byte) (*FrameWriter, error) {
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}
	return &FrameWriter{w: w, aead: aead}, nil
}

// WriteFrame encrypts plaintext as a single frame of the given type.
// Large payloads must be split by the caller (use Write for automatic splitting).
func (fw *FrameWriter) WriteFrame(frameType byte, plaintext []byte) error {
	nonce := MakeNonce(fw.counter)
	fw.counter++
	ciphertext := fw.aead.Seal(nil, nonce, plaintext, nil)

	header := [3]byte{}
	binary.BigEndian.PutUint16(header[0:2], uint16(len(ciphertext)))
	header[2] = frameType

	if _, err := fw.w.Write(header[:]); err != nil {
		return err
	}
	_, err := fw.w.Write(ciphertext)
	return err
}

// Write implements io.Writer by splitting p into MaxFramePayload-sized DATA frames.
func (fw *FrameWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > MaxFramePayload {
			chunk = p[:MaxFramePayload]
		}
		if err := fw.WriteFrame(FrameTypeData, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// WriteClose sends a CLOSE frame to signal the end of the session.
func (fw *FrameWriter) WriteClose() error {
	return fw.WriteFrame(FrameTypeClose, nil)
}

// FrameReader decrypts incoming Reflex frames from the underlying io.Reader and
// presents the plaintext as a plain io.Reader.
type FrameReader struct {
	r       io.Reader
	aead    cipher.AEAD
	counter uint64
	buf     []byte
	closed  bool
}

// NewFrameReader creates a FrameReader that decrypts frames using sessionKey.
func NewFrameReader(r io.Reader, sessionKey []byte) (*FrameReader, error) {
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}
	return &FrameReader{r: r, aead: aead}, nil
}

// Read implements io.Reader.  It transparently handles multiple frame types,
// skipping PADDING/TIMING control frames and returning io.EOF on CLOSE.
func (fr *FrameReader) Read(p []byte) (int, error) {
	for {
		// Return any buffered plaintext first.
		if len(fr.buf) > 0 {
			n := copy(p, fr.buf)
			fr.buf = fr.buf[n:]
			return n, nil
		}
		if fr.closed {
			return 0, io.EOF
		}

		// Read the 3-byte frame header.
		header := make([]byte, 3)
		if _, err := io.ReadFull(fr.r, header); err != nil {
			return 0, err
		}
		length := binary.BigEndian.Uint16(header[0:2])
		frameType := header[2]

		// Read the ciphertext.
		ciphertext := make([]byte, length)
		if _, err := io.ReadFull(fr.r, ciphertext); err != nil {
			return 0, err
		}

		// Decrypt.
		nonce := MakeNonce(fr.counter)
		fr.counter++
		plaintext, err := fr.aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return 0, err
		}

		switch frameType {
		case FrameTypeData:
			n := copy(p, plaintext)
			if n < len(plaintext) {
				fr.buf = plaintext[n:] // save the rest
			}
			return n, nil
		case FrameTypeClose:
			fr.closed = true
			return 0, io.EOF
		// PADDING and TIMING control frames carry no user data; silently skip.
		case FrameTypePadding, FrameTypeTiming:
			continue
		default:
			// Unknown frame type – skip.
			continue
		}
	}
}
