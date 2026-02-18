// Package inbound implements the Reflex inbound (server-side) proxy handler.
package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

// Handler is the Reflex inbound connection handler.
type Handler struct {
	clients       []*protocol.MemoryUser
	fallbackPort  uint32
	hasFallback   bool
	policyManager policy.Manager
}

// New creates a new Reflex inbound Handler from the given config.
func New(ctx context.Context, config *reflex.InboundConfig) (*Handler, error) {
	h := &Handler{
		clients: make([]*protocol.MemoryUser, 0, len(config.Clients)),
	}

	for _, client := range config.Clients {
		h.clients = append(h.clients, &protocol.MemoryUser{
			Email: client.Id,
			Account: &MemoryAccount{
				Id: client.Id,
			},
		})
	}

	if config.Fallback != nil && config.Fallback.Dest > 0 {
		h.fallbackPort = config.Fallback.Dest
		h.hasFallback = true
	}

	// Retrieve the policy manager from the Xray core in context.
	v := core.MustFromContext(ctx)
	h.policyManager = v.GetFeature(policy.ManagerType()).(policy.Manager)

	return h, nil
}

// MemoryAccount represents an authenticated Reflex user in memory.
type MemoryAccount struct {
	Id string
}

// Equals implements protocol.Account.
func (a *MemoryAccount) Equals(other protocol.Account) bool {
	o, ok := other.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.Id == o.Id
}

// ToProto implements protocol.Account.
// Returns the account ID wrapped in a StringValue proto message.
func (a *MemoryAccount) ToProto() proto.Message {
	return wrapperspb.String(a.Id)
}

// Network implements proxy.Inbound.
func (h *Handler) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP}
}

// preloadedConn wraps a bufio.Reader and the original stat.Connection so that
// bytes already peeked (and buffered in the Reader) are re-delivered on Read,
// while writes still go directly to the underlying connection.
//
// This is the canonical pattern for forwarding peeked bytes to a fallback
// server: because the bufio.Reader buffers peeked data, callers that read
// from preloadedConn will receive those bytes before any new network reads.
type preloadedConn struct {
	*bufio.Reader
	stat.Connection
}

// Read satisfies io.Reader: data comes from the buffered reader first.
func (pc *preloadedConn) Read(b []byte) (int, error) { return pc.Reader.Read(b) }

// Write satisfies io.Writer: writes go to the underlying network connection.
func (pc *preloadedConn) Write(b []byte) (int, error) { return pc.Connection.Write(b) }

// Process implements proxy.Inbound.  It is called for every new TCP connection.
//
// Flow:
//  1. Peek the first MinHandshakePeekSize bytes (bufio.Reader – no consumption).
//  2. Detect Reflex magic → parse handshake, relay with frame encryption.
//  3. Detect HTTP POST-like header → parse handshake from HTTP body, relay.
//  4. Otherwise → forward raw bytes (including peeked ones) to fallback port.
func (h *Handler) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	sessionPolicy := h.policyManager.ForLevel(0)

	// Apply a handshake deadline so slow/probing connections don't linger.
	if err := conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		errors.LogWarningInner(ctx, err, "reflex: unable to set handshake deadline")
	}

	// Buffer the connection so we can peek without consuming bytes.
	// The buffer must be at least MinHandshakePeekSize to allow Peek to succeed.
	const bufSize = reflex.MinHandshakePeekSize * 4
	br := bufio.NewReaderSize(conn, bufSize)

	// Peek enough bytes to detect the protocol.  Use MinHandshakePeekSize so
	// both the magic-number path and the HTTP-header path can make a decision.
	// Even if fewer bytes arrive (short connection), Peek returns what is
	// available together with an error; we handle that by falling back.
	peeked, peekErr := br.Peek(reflex.MinHandshakePeekSize)
	if peekErr != nil && len(peeked) < 4 {
		// Not enough data to identify the protocol.
		return errors.New("reflex: connection closed before handshake").Base(peekErr)
	}

	// Fast path: binary magic number.
	if reflex.IsReflexMagic(peeked) {
		return h.handleReflexMagic(ctx, br, conn, dispatcher, sessionPolicy)
	}

	// Covert path: HTTP POST disguise.
	if reflex.IsHTTPPostLike(peeked) {
		return h.handleHTTPPost(ctx, br, conn, dispatcher, sessionPolicy)
	}

	// Not a Reflex connection – forward to fallback.
	// Crucially, br still holds the peeked bytes in its buffer, so the
	// fallback server will receive the complete original byte stream.
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		errors.LogWarningInner(ctx, err, "reflex: unable to clear read deadline")
	}
	return h.doFallback(ctx, br, conn, sessionPolicy)
}

// -------------------------------------------------------------------
// handleReflexMagic – binary magic-number detection path
// -------------------------------------------------------------------

// handleReflexMagic reads and processes a Reflex handshake that starts with the
// 4-byte magic number.
//
// Wire format after the magic:
//
//	[32 bytes] client X25519 public key
//	[16 bytes] user UUID
//	[12 bytes] PSK nonce
//	[4  bytes] encrypted payload length (big-endian uint32)
//	[N  bytes] encrypted payload (ChaCha20-Poly1305 with PSK)
//
// Encrypted payload plaintext:
//
//	[1 byte]  addr type  (0x01=IPv4, 0x02=domain, 0x03=IPv6)
//	[varies]  address
//	[2 bytes] destination port (big-endian uint16)
func (h *Handler) handleReflexMagic(ctx context.Context, br *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, sessionPolicy policy.Session) error {
	// Consume the 4-byte magic.
	if _, err := io.ReadFull(br, make([]byte, 4)); err != nil {
		return errors.New("reflex: failed to read magic").Base(err)
	}

	// Read client public key (32 bytes).
	var clientPubKey [32]byte
	if _, err := io.ReadFull(br, clientPubKey[:]); err != nil {
		return errors.New("reflex: failed to read client public key").Base(err)
	}

	// Read user UUID (16 bytes).
	var userID [16]byte
	if _, err := io.ReadFull(br, userID[:]); err != nil {
		return errors.New("reflex: failed to read user ID").Base(err)
	}

	// Read PSK nonce (12 bytes).
	pskNonce := make([]byte, 12)
	if _, err := io.ReadFull(br, pskNonce); err != nil {
		return errors.New("reflex: failed to read PSK nonce").Base(err)
	}

	// Read encrypted payload length (4 bytes).
	var payloadLenBuf [4]byte
	if _, err := io.ReadFull(br, payloadLenBuf[:]); err != nil {
		return errors.New("reflex: failed to read payload length").Base(err)
	}
	payloadLen := binary.BigEndian.Uint32(payloadLenBuf[:])
	if payloadLen > 4096 {
		return h.doFallback(ctx, br, conn, sessionPolicy)
	}

	// Read the encrypted payload.
	encPayload := make([]byte, payloadLen)
	if _, err := io.ReadFull(br, encPayload); err != nil {
		return errors.New("reflex: failed to read encrypted payload").Base(err)
	}

	return h.processHandshake(ctx, br, conn, dispatcher, sessionPolicy, clientPubKey, userID, pskNonce, encPayload)
}

// -------------------------------------------------------------------
// handleHTTPPost – HTTP POST-like detection path
// -------------------------------------------------------------------

// handleHTTPPost parses a minimal HTTP POST request that carries the encoded
// Reflex handshake in a custom header "X-Reflex-Data".
//
// Expected header (everything else is ignored):
//
//	POST /api/v1/endpoint HTTP/1.1
//	X-Reflex-Data: <hex-encoded handshake bytes>
//
// The hex data encodes the same payload as above (minus the 4-byte magic):
// clientPubKey(32) + userID(16) + pskNonce(12) + payloadLen(4) + encPayload(N)
func (h *Handler) handleHTTPPost(ctx context.Context, br *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, sessionPolicy policy.Session) error {
	// Read HTTP headers line by line.
	const maxHeaders = 32
	reflexData := ""
	for i := 0; i < maxHeaders; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			return h.doFallback(ctx, br, conn, sessionPolicy)
		}
		// Trim \r\n
		if len(line) >= 2 {
			line = line[:len(line)-2]
		}
		if line == "" {
			break // end of headers
		}
		// Look for our custom header
		const prefix = "X-Reflex-Data: "
		if len(line) > len(prefix) && line[:len(prefix)] == prefix {
			reflexData = line[len(prefix):]
		}
	}

	if reflexData == "" {
		// No Reflex data found – fall back.
		return h.doFallback(ctx, br, conn, sessionPolicy)
	}

	// Hex-decode the data.
	data := make([]byte, len(reflexData)/2)
	if _, err := hexDecodeString(reflexData, data); err != nil {
		return h.doFallback(ctx, br, conn, sessionPolicy)
	}

	if len(data) < 32+16+12+4 {
		return h.doFallback(ctx, br, conn, sessionPolicy)
	}

	var clientPubKey [32]byte
	copy(clientPubKey[:], data[0:32])
	var userID [16]byte
	copy(userID[:], data[32:48])
	pskNonce := data[48:60]
	payloadLen := binary.BigEndian.Uint32(data[60:64])
	if uint32(len(data)) < 64+payloadLen {
		return h.doFallback(ctx, br, conn, sessionPolicy)
	}
	encPayload := data[64 : 64+payloadLen]

	// Send a 200 response header before the binary handshake reply.
	conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n"))

	return h.processHandshake(ctx, br, conn, dispatcher, sessionPolicy, clientPubKey, userID, pskNonce, encPayload)
}

// hexDecodeString decodes a lowercase hex string into dst.
func hexDecodeString(s string, dst []byte) (int, error) {
	for i := 0; i < len(s)-1 && i/2 < len(dst); i += 2 {
		hi := hexVal(s[i])
		lo := hexVal(s[i+1])
		if hi > 15 || lo > 15 {
			return i / 2, errors.New("invalid hex character")
		}
		dst[i/2] = hi<<4 | lo
	}
	return len(s) / 2, nil
}

func hexVal(c byte) byte {
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

// -------------------------------------------------------------------
// processHandshake – common Diffie-Hellman + auth + session setup
// -------------------------------------------------------------------

func (h *Handler) processHandshake(
	ctx context.Context,
	br *bufio.Reader,
	conn stat.Connection,
	dispatcher routing.Dispatcher,
	sessionPolicy policy.Session,
	clientPubKey [32]byte,
	userID [16]byte,
	pskNonce []byte,
	encPayload []byte,
) error {
	// --- Authenticate user ---
	user := h.findUser(userID)
	if user == nil {
		log.Record(&log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     "",
			Status: log.AccessRejected,
			Reason: errors.New("reflex: unknown user"),
		})
		return h.doFallback(ctx, br, conn, sessionPolicy)
	}

	// --- Decrypt the destination payload using the PSK ---
	psk, err := reflex.DerivePSK(userID)
	if err != nil {
		return errors.New("reflex: failed to derive PSK").Base(err)
	}
	pskAEAD, err := chacha20poly1305.New(psk)
	if err != nil {
		return errors.New("reflex: failed to create PSK cipher").Base(err)
	}
	plainPayload, err := pskAEAD.Open(nil, pskNonce, encPayload, nil)
	if err != nil {
		// PSK decryption failed – invalid client, fall back.
		return h.doFallback(ctx, br, conn, sessionPolicy)
	}

	// Parse destination from plainPayload.
	dest, consumed, err := parseDestination(plainPayload)
	if err != nil {
		return errors.New("reflex: failed to parse destination").Base(err)
	}
	_ = consumed // remaining bytes could be policy request (ignored for now)

	// --- Key exchange ---
	serverPrivKey, serverPubKey, err := reflex.GenerateKeyPair()
	if err != nil {
		return errors.New("reflex: failed to generate server key pair").Base(err)
	}
	sharedSecret, err := reflex.DeriveSharedSecret(serverPrivKey, clientPubKey)
	if err != nil {
		return errors.New("reflex: failed to derive shared secret").Base(err)
	}

	// salt = userID || pskNonce for session key derivation
	salt := make([]byte, 16+len(pskNonce))
	copy(salt[0:16], userID[:])
	copy(salt[16:], pskNonce)
	sessionKey, err := reflex.DeriveSessionKey(sharedSecret, salt)
	if err != nil {
		return errors.New("reflex: failed to derive session key").Base(err)
	}

	// --- Send server handshake response ---
	// [32 bytes server public key][1 byte status 0x00]
	response := make([]byte, 33)
	copy(response[0:32], serverPubKey[:])
	response[32] = 0x00 // OK
	if _, err := conn.Write(response); err != nil {
		return errors.New("reflex: failed to write server handshake").Base(err)
	}

	// Clear the handshake deadline.
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		errors.LogWarningInner(ctx, err, "reflex: unable to clear read deadline")
	}

	// --- Set up the encrypted session ---
	// The client encrypts data it sends → server decrypts with sessionKey.
	// The server encrypts data it sends → client decrypts with sessionKey.
	// Both sides use independent send counters (they start at 0 each).
	frameReader, err := reflex.NewFrameReader(conn, sessionKey)
	if err != nil {
		return errors.New("reflex: failed to create frame reader").Base(err)
	}
	frameWriter, err := reflex.NewFrameWriter(conn, sessionKey)
	if err != nil {
		return errors.New("reflex: failed to create frame writer").Base(err)
	}

	// Update session context.
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inbound.Name = "reflex"
		inbound.User = user
	}
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  user.Email,
	})
	errors.LogInfo(ctx, "reflex: accepted connection to ", dest)

	return h.relay(ctx, sessionPolicy, dest, frameReader, frameWriter, dispatcher)
}

// -------------------------------------------------------------------
// relay – dispatch to destination and copy data bidirectionally
// -------------------------------------------------------------------

func (h *Handler) relay(
	ctx context.Context,
	sessionPolicy policy.Session,
	destination xnet.Destination,
	clientReader io.Reader,
	clientWriter *reflex.FrameWriter,
	dispatcher routing.Dispatcher,
) error {
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		return errors.New("reflex: failed to dispatch to ", destination).Base(err)
	}

	// client → upstream
	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		if err := buf.Copy(buf.NewReader(clientReader), link.Writer, buf.UpdateActivity(timer)); err != nil {
			return errors.New("reflex: upload ended").Base(err)
		}
		return nil
	}

	// upstream → client (with frame encryption)
	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		if err := buf.Copy(link.Reader, buf.NewWriter(clientWriter), buf.UpdateActivity(timer)); err != nil {
			return errors.New("reflex: download ended").Base(err)
		}
		return nil
	}

	if err := task.Run(ctx,
		task.OnSuccess(requestDone, task.Close(link.Writer)),
		responseDone,
	); err != nil {
		common.Must(common.Interrupt(link.Reader))
		common.Must(common.Interrupt(link.Writer))
		return errors.New("reflex: session ended").Base(err)
	}
	return nil
}

// -------------------------------------------------------------------
// Fallback
// -------------------------------------------------------------------

// doFallback forwards the buffered + remaining bytes to the configured
// fallback port on localhost, providing active-probe resistance.
func (h *Handler) doFallback(ctx context.Context, br *bufio.Reader, conn stat.Connection, sessionPolicy policy.Session) error {
	if !h.hasFallback {
		return errors.New("reflex: not a Reflex connection and no fallback configured")
	}

	errors.LogInfo(ctx, "reflex: forwarding to fallback port ", h.fallbackPort)

	fbAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(h.fallbackPort)}
	fbConn, err := net.DialTCP("tcp", nil, fbAddr)
	if err != nil {
		return errors.New("reflex: failed to connect to fallback").Base(err)
	}
	defer fbConn.Close()

	_ = sessionPolicy // timeouts enforced by the caller's connection deadline if needed

	var wg sync.WaitGroup
	wg.Add(2)

	// client → fallback: forward the buffered reader (peeked bytes included)
	// then half-close the write side so the fallback server sees EOF.
	go func() {
		defer wg.Done()
		io.Copy(fbConn, br) //nolint:errcheck
		// Half-close: signal EOF to fallback server while keeping read side open.
		fbConn.CloseWrite() //nolint:errcheck
	}()

	// fallback → client: relay any response back.
	go func() {
		defer wg.Done()
		io.Copy(conn, fbConn) //nolint:errcheck
	}()

	wg.Wait()
	return nil
}

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

// findUser returns the MemoryUser whose UUID matches userID, or nil.
func (h *Handler) findUser(userID [16]byte) *protocol.MemoryUser {
	idStr := formatUUID(userID)
	for _, u := range h.clients {
		if u.Email == idStr {
			return u
		}
	}
	return nil
}

// formatUUID converts a raw 16-byte UUID to the standard dashed string form.
func formatUUID(b [16]byte) string {
	const hex = "0123456789abcdef"
	var buf [36]byte
	dst := buf[:]
	src := b[:]
	groups := []int{4, 2, 2, 2, 6}
	pos := 0
	for gi, g := range groups {
		for i := 0; i < g; i++ {
			dst[pos] = hex[src[0]>>4]
			dst[pos+1] = hex[src[0]&0xf]
			pos += 2
			src = src[1:]
		}
		if gi < 4 {
			dst[pos] = '-'
			pos++
		}
	}
	return string(buf[:])
}

// parseDestination reads address type + address + port from the decrypted payload.
// Returns the net.Destination and the number of bytes consumed.
func parseDestination(p []byte) (xnet.Destination, int, error) {
	if len(p) < 1 {
		return xnet.Destination{}, 0, errors.New("payload too short for addr type")
	}
	addrType := p[0]
	p = p[1:]
	consumed := 1

	var addr xnet.Address
	switch addrType {
	case reflex.AddrTypeIPv4:
		if len(p) < 4 {
			return xnet.Destination{}, 0, errors.New("payload too short for IPv4")
		}
		addr = xnet.IPAddress(p[0:4])
		p = p[4:]
		consumed += 4
	case reflex.AddrTypeIPv6:
		if len(p) < 16 {
			return xnet.Destination{}, 0, errors.New("payload too short for IPv6")
		}
		addr = xnet.IPAddress(p[0:16])
		p = p[16:]
		consumed += 16
	case reflex.AddrTypeDomain:
		if len(p) < 1 {
			return xnet.Destination{}, 0, errors.New("payload too short for domain length")
		}
		domLen := int(p[0])
		p = p[1:]
		consumed++
		if len(p) < domLen {
			return xnet.Destination{}, 0, errors.New("payload too short for domain")
		}
		addr = xnet.DomainAddress(string(p[:domLen]))
		p = p[domLen:]
		consumed += domLen
	default:
		return xnet.Destination{}, 0, errors.New("unknown addr type: ", addrType)
	}

	if len(p) < 2 {
		return xnet.Destination{}, 0, errors.New("payload too short for port")
	}
	port := xnet.Port(binary.BigEndian.Uint16(p[0:2]))
	consumed += 2

	dest := xnet.TCPDestination(addr, port)
	return dest, consumed, nil
}
