// Package reflex implements the Reflex proxy protocol.
// Reflex is a protocol designed for censorship resistance with:
// - Implicit handshake (hidden inside normal-looking packets)
// - Fallback support (active probe resistance)
// - ChaCha20-Poly1305 frame encryption
// - X25519 key exchange + HKDF key derivation
package reflex

// User represents a Reflex user with an ID and traffic policy.
type User struct {
	Id     string
	Policy string
}

// Account is the in-memory representation of a Reflex account.
// Used for user authentication lookup.
type Account struct {
	Id string
}

// InboundConfig holds the configuration for the Reflex inbound (server) handler.
type InboundConfig struct {
	Clients  []*User
	Fallback *FallbackDest
}

// FallbackDest configures the port to which non-Reflex connections are forwarded.
// This provides active-probe resistance: probers see a normal web server.
type FallbackDest struct {
	Dest uint32 // TCP port on localhost (e.g., 80 for nginx)
}

// OutboundConfig holds the configuration for the Reflex outbound (client) handler.
type OutboundConfig struct {
	Address string // Server address
	Port    uint32 // Server port
	Id      string // User UUID
}
