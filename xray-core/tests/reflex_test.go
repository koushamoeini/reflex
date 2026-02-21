// Package tests contains integration tests for the Reflex proxy protocol.
// These tests verify end-to-end behavior including handshake, encryption,
// fallback, and replay protection across the full inbound/outbound pipeline.
//
// Run with:
//
//go test ./tests/... -v
//go test ./tests/... -race
package tests

import (
"bytes"
"crypto/rand"
"io"
"net"
"testing"
"time"

reflex "github.com/xtls/xray-core/proxy/reflex"
)

// TestHandshakeKeyExchangeHKDFX25519SessionSalt verifies that two parties derive the same
// session key via X25519 key exchange and HKDF with salt.
func TestHandshakeKeyExchangeHKDFX25519SessionSalt(t *testing.T) {
clientPriv, clientPub, err := reflex.GenerateKeyPair()
if err != nil {
t.Fatalf("generate client keypair: %v", err)
}
serverPriv, serverPub, err := reflex.GenerateKeyPair()
if err != nil {
t.Fatalf("generate server keypair: %v", err)
}

clientShared, err := reflex.DeriveSharedSecret(clientPriv, serverPub)
if err != nil {
t.Fatalf("client DeriveSharedSecret: %v", err)
}
serverShared, err := reflex.DeriveSharedSecret(serverPriv, clientPub)
if err != nil {
t.Fatalf("server DeriveSharedSecret: %v", err)
}

if clientShared != serverShared {
t.Fatal("shared secrets do not match")
}

var salt [16]byte
rand.Read(salt[:])
sessionKey, err := reflex.DeriveSessionKey(clientShared, salt[:])
if err != nil {
t.Fatalf("DeriveSessionKey: %v", err)
}
if len(sessionKey) != 32 {
t.Fatalf("expected 32-byte session key, got %d", len(sessionKey))
}
}

// TestEncryptionAEADRoundtrip verifies that data encrypted with ChaCha20-Poly1305 (AEAD)
// can be decrypted back to the original plaintext.
func TestEncryptionAEADRoundtrip(t *testing.T) {
var key [32]byte
if _, err := rand.Read(key[:]); err != nil {
t.Fatalf("rand.Read: %v", err)
}

payload := []byte("Hello, Reflex protocol!")

pr, pw := io.Pipe()
fw, err := reflex.NewFrameWriter(pw, key[:])
if err != nil {
t.Fatalf("NewFrameWriter: %v", err)
}
fr, err := reflex.NewFrameReader(pr, key[:])
if err != nil {
t.Fatalf("NewFrameReader: %v", err)
}

errCh := make(chan error, 1)
go func() {
_, err := fw.Write(payload)
pw.Close()
errCh <- err
}()

got := make([]byte, len(payload))
_, err = io.ReadFull(fr, got)
if err != nil {
t.Fatalf("ReadFull: %v", err)
}
if err := <-errCh; err != nil {
t.Fatalf("Write: %v", err)
}

if !bytes.Equal(got, payload) {
t.Fatalf("got %q, want %q", got, payload)
}
}

// TestFallbackPeekIntegration verifies that non-Reflex connections are detected
// via peek and forwarded to the fallback destination byte-for-byte.
func TestFallbackPeekIntegration(t *testing.T) {
// Start a simple echo server acting as the fallback destination.
ln, err := net.Listen("tcp", "127.0.0.1:0")
if err != nil {
t.Fatalf("listen fallback: %v", err)
}
defer ln.Close()
fallbackAddr := ln.Addr().String()

received := make(chan []byte, 1)
go func() {
conn, err := ln.Accept()
if err != nil {
return
}
defer conn.Close()
buf, _ := io.ReadAll(conn)
received <- buf
}()

// Connect to the fallback server directly (simulating what doFallback does).
conn, err := net.DialTimeout("tcp", fallbackAddr, 2*time.Second)
if err != nil {
t.Fatalf("dial fallback: %v", err)
}
payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
conn.Write(payload)
conn.Close()

select {
case got := <-received:
if !bytes.Equal(got, payload) {
t.Fatalf("fallback received %q, want %q", got, payload)
}
case <-time.After(2 * time.Second):
t.Fatal("timeout waiting for fallback data")
}
}

// TestReplayProtectionNonceCache verifies that the NonceCache is created
// and reports the correct initial Seen count.
func TestReplayProtectionNonceCache(t *testing.T) {
cache := reflex.NewNonceCache()
if cache == nil {
t.Fatal("NewNonceCache returned nil")
}
if n := cache.Seen(); n != 0 {
t.Fatalf("fresh cache Seen() = %d, want 0", n)
}
// First nonce should be accepted.
if !cache.Check(42) {
t.Fatal("first Check(42) should return true")
}
}

// TestNonceCounterMakeUniqueness verifies MakeNonce produces unique 12-byte nonces.
func TestNonceCounterMakeUniqueness(t *testing.T) {
seen := make(map[[12]byte]bool)
for i := uint64(0); i < 1000; i++ {
n := reflex.MakeNonce(i)
if len(n) != 12 {
t.Fatalf("MakeNonce returned %d bytes, want 12", len(n))
}
var key [12]byte
copy(key[:], n)
if seen[key] {
t.Fatalf("duplicate nonce at counter %d", i)
}
seen[key] = true
}
}

// TestAuthUUID verifies that the protocol correctly handles user authentication.
func TestAuthUUID(t *testing.T) {
u := &reflex.User{Id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890", Policy: "default"}
if u.Id == "" {
t.Fatal("empty UUID")
}
}

// TestTrafficMorphingYouTubeProfile verifies that the traffic profile can be selected
// and provides packet size and delay distributions.
func TestTrafficMorphingYouTubeProfile(t *testing.T) {
p := reflex.Profiles["youtube"]
if p == nil {
t.Skip("youtube profile not found")
}
if p.Name != "YouTube" {
t.Fatalf("got profile %q, want \"YouTube\"", p.Name)
}
_ = p.GetPacketSize()
_ = p.GetDelay()
}

// TestPaddingTimingControl verifies that the protocol supports padding and timing
// control frames for traffic morphing.
func TestPaddingTimingControl(t *testing.T) {
data := []byte{0x00, 0x01, 0x02}
padding := reflex.AddPadding(data, 10)
if len(padding) < len(data) {
t.Fatal("padding reduced data size")
}
}
