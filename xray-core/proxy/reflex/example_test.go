// Package reflex_test provides examples for the public Reflex protocol API.
package reflex_test

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/xtls/xray-core/proxy/reflex"
)

// ─────────────────────────────────────────────────────────────────────────────
// Session examples
// ─────────────────────────────────────────────────────────────────────────────

// ExampleNewSession demonstrates creating a new Reflex session from a 32-byte
// ChaCha20-Poly1305 session key.
func ExampleNewSession() {
	// Session keys are derived from the X25519 shared secret via HKDF.
	// In practice, use DeriveSessionKey; here we use a hard-coded key.
	sessionKey := make([]byte, 32) // 32 zeros for illustration only

	session, err := reflex.NewSession(sessionKey)
	if err != nil {
		panic(err)
	}

	_ = session
	fmt.Println("session created")
	// Output:
	// session created
}

// ExampleSession_WriteFrame shows how to encrypt and send a DATA frame.
func ExampleSession_WriteFrame() {
	key := make([]byte, 32)
	sender, _ := reflex.NewSession(key)
	receiver, _ := reflex.NewSession(key)

	var wire bytes.Buffer

	// Send a DATA frame.
	payload := []byte("hello reflex")
	if err := sender.WriteFrame(&wire, reflex.FrameTypeData, payload); err != nil {
		panic(err)
	}

	// Receive and decrypt.
	frame, err := receiver.ReadFrame(&wire)
	if err != nil {
		panic(err)
	}

	fmt.Printf("type=0x%02x payload=%q\n", frame.Type, frame.Payload)
	// Output:
	// type=0x01 payload="hello reflex"
}

// ExampleSession_ReadFrame shows the read side of the Session API.
func ExampleSession_ReadFrame() {
	key := make([]byte, 32)
	writer, _ := reflex.NewSession(key)
	reader, _ := reflex.NewSession(key)

	var wire bytes.Buffer
	_ = writer.WriteFrame(&wire, reflex.FrameTypeData, []byte("ping"))

	frame, _ := reader.ReadFrame(&wire)
	fmt.Println(string(frame.Payload))
	// Output:
	// ping
}

// ─────────────────────────────────────────────────────────────────────────────
// Key exchange examples
// ─────────────────────────────────────────────────────────────────────────────

// ExampleGenerateKeyPair shows how to create an X25519 key pair.
func ExampleGenerateKeyPair() {
	priv, pub, err := reflex.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	// In a real handshake the public key is sent to the peer.
	_ = priv
	fmt.Printf("public key: %d bytes\n", len(pub))
	// Output:
	// public key: 32 bytes
}

// ExampleDeriveSessionKey demonstrates the full key-exchange flow between a
// client and server using X25519 + HKDF.
func ExampleDeriveSessionKey() {
	// Both sides generate ephemeral key pairs.
	clientPriv, clientPub, _ := reflex.GenerateKeyPair()
	serverPriv, serverPub, _ := reflex.GenerateKeyPair()

	// Exchange public keys (sent over the wire in the handshake).
	clientShared, _ := reflex.DeriveSharedSecret(clientPriv, serverPub)
	serverShared, _ := reflex.DeriveSharedSecret(serverPriv, clientPub)

	// HKDF derives identical session keys on both sides.
	salt := []byte("example-salt")
	clientKey, _ := reflex.DeriveSessionKey(clientShared, salt)
	serverKey, _ := reflex.DeriveSessionKey(serverShared, salt)

	fmt.Println("keys match:", bytes.Equal(clientKey, serverKey))
	// Output:
	// keys match: true
}

// ─────────────────────────────────────────────────────────────────────────────
// FrameWriter / FrameReader examples
// ─────────────────────────────────────────────────────────────────────────────

// ExampleNewFrameWriter shows how to stream encrypted data using FrameWriter.
func ExampleNewFrameWriter() {
	key := make([]byte, 32)
	var wire bytes.Buffer

	fw, _ := reflex.NewFrameWriter(&wire, key)
	fr, _ := reflex.NewFrameReader(&wire, key)

	// Write transparently splits data into MaxFramePayload-sized frames.
	data := []byte("streaming payload")
	fw.Write(data)
	fw.WriteClose() // signals end of stream

	got, _ := io.ReadAll(fr) // reads until CLOSE frame
	fmt.Println(string(got))
	// Output:
	// streaming payload
}

// ─────────────────────────────────────────────────────────────────────────────
// Protocol detection examples
// ─────────────────────────────────────────────────────────────────────────────

// ExampleIsReflexMagic demonstrates the magic-byte protocol detector.
func ExampleIsReflexMagic() {
	fmt.Println(reflex.IsReflexMagic(reflex.ReflexMagic()))
	fmt.Println(reflex.IsReflexMagic([]byte("GET / HTTP/1.1")))
	// Output:
	// true
	// false
}

// ExampleIsHTTPPostLike demonstrates the HTTP POST protocol detector used for
// the covert channel disguise.
func ExampleIsHTTPPostLike() {
	fmt.Println(reflex.IsHTTPPostLike([]byte("POST /api HTTP/1.1\r\n")))
	fmt.Println(reflex.IsHTTPPostLike([]byte("GET / HTTP/1.1\r\n")))
	// Output:
	// true
	// false
}

// ─────────────────────────────────────────────────────────────────────────────
// NonceCache examples
// ─────────────────────────────────────────────────────────────────────────────

// ExampleNonceCache demonstrates replay-attack protection.
func ExampleNewNonceCache() {
	nc := reflex.NewNonceCache()

	fmt.Println("first:", nc.Check(42))  // fresh
	fmt.Println("replay:", nc.Check(42)) // duplicate
	fmt.Println("next:", nc.Check(43))   // fresh
	// Output:
	// first: true
	// replay: false
	// next: true
}

// ─────────────────────────────────────────────────────────────────────────────
// Traffic Morphing examples
// ─────────────────────────────────────────────────────────────────────────────

// ExampleTrafficProfile demonstrates building a custom profile from capture data.
func ExampleCreateProfileFromCapture() {
	// Packet sizes and inter-packet delays extracted from a real capture.
	sizes := []int{1400, 1400, 1200, 1200, 1200, 1000}
	delays := []time.Duration{
		8 * time.Millisecond,
		8 * time.Millisecond,
		12 * time.Millisecond,
	}

	profile := reflex.CreateProfileFromCapture("my-app", sizes, delays)
	fmt.Println("profile:", profile.Name)
	fmt.Println("size buckets:", len(profile.PacketSizes))
	fmt.Println("delay buckets:", len(profile.Delays))
	// Output:
	// profile: my-app
	// size buckets: 3
	// delay buckets: 2
}

// ExampleKolmogorovSmirnovTest shows how to use the KS-test to verify that
// morphed traffic matches the reference distribution.
func ExampleKolmogorovSmirnovTest() {
	// Two samples from the same distribution should be statistically similar.
	profile := &reflex.TrafficProfile{
		Name:        "test",
		PacketSizes: []reflex.PacketSizeDist{{Size: 1000, Weight: 1.0}},
		Delays:      []reflex.DelayDist{{Delay: 0, Weight: 1.0}},
	}

	s1 := reflex.GenerateMorphedSizes(profile, 200)
	s2 := reflex.GenerateMorphedSizes(profile, 200)

	res := reflex.KolmogorovSmirnovTest(s1, s2)
	// For identical distributions the statistic is 0 and p-value is 1.
	fmt.Printf("D=%.2f indistinguishable=%v\n", res.Statistic, res.PValue >= 0.05)
	// Output:
	// D=0.00 indistinguishable=true
}

// ExampleSession_WriteFrameWithMorphing shows how to send morphed frames that
// mimic a specific traffic profile.
func ExampleSession_WriteFrameWithMorphing() {
	key := make([]byte, 32)
	sender, _ := reflex.NewSession(key)

	// Zero-delay profile so the example is instant.
	profile := &reflex.TrafficProfile{
		Name:        "demo",
		PacketSizes: []reflex.PacketSizeDist{{Size: 100, Weight: 1.0}},
		Delays:      []reflex.DelayDist{{Delay: 0, Weight: 1.0}},
	}

	var wire bytes.Buffer
	err := sender.WriteFrameWithMorphing(&wire, reflex.FrameTypeData, []byte("hi"), profile)
	if err != nil {
		panic(err)
	}
	// The frame is padded to 100 bytes internally, but decrypted payload is
	// the same as what was sent (the receiver strips padding after decryption).
	fmt.Println("morphed frame sent:", wire.Len() > 0)
	// Output:
	// morphed frame sent: true
}
