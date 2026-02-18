// Package outbound implements the Reflex outbound (client-side) proxy handler.
package outbound

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"

	"golang.org/x/crypto/chacha20poly1305"
)

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.OutboundConfig))
	}))
}

// Client is the Reflex outbound handler.
type Client struct {
	serverAddr    xnet.Destination
	userID        [16]byte
	policyManager policy.Manager
}

// New creates a new Reflex outbound Client from the given config.
func New(ctx context.Context, config *reflex.OutboundConfig) (*Client, error) {
	uid, err := parseUUID(config.Id)
	if err != nil {
		return nil, errors.New("reflex outbound: invalid user ID: ", config.Id).Base(err)
	}

	addr := xnet.ParseAddress(config.Address)
	port := xnet.Port(config.Port)

	v := core.MustFromContext(ctx)
	pm := v.GetFeature(policy.ManagerType()).(policy.Manager)

	return &Client{
		serverAddr:    xnet.TCPDestination(addr, port),
		userID:        uid,
		policyManager: pm,
	}, nil
}

// Process implements proxy.Outbound.
//
// Flow:
//  1. Dial the configured Reflex server.
//  2. Generate a client X25519 key pair.
//  3. Encrypt the destination address with the PSK.
//  4. Send the Reflex handshake (magic + clientPubKey + userID + pskNonce + encPayload).
//  5. Read the server handshake response (serverPubKey + status).
//  6. Derive the session key.
//  7. Relay application data with frame encryption in both directions.
func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("reflex: target not specified")
	}
	ob.Name = "reflex"
	destination := ob.Target

	// Dial the Reflex server.
	var conn stat.Connection
	var dialErr error
	conn, dialErr = dialer.Dial(ctx, c.serverAddr)
	if dialErr != nil {
		return errors.New("reflex: failed to dial server").Base(dialErr)
	}
	defer conn.Close()

	errors.LogInfo(ctx, "reflex: tunnelling request to ", destination, " via ", c.serverAddr.NetAddr())

	sessionPolicy := c.policyManager.ForLevel(0)

	// --- Build and send the client handshake ---

	// 1) Generate ephemeral key pair.
	clientPrivKey, clientPubKey, err := reflex.GenerateKeyPair()
	if err != nil {
		return errors.New("reflex: failed to generate key pair").Base(err)
	}

	// 2) Generate a PSK nonce (12 random bytes).
	pskNonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, pskNonce); err != nil {
		return errors.New("reflex: failed to generate PSK nonce").Base(err)
	}

	// 3) Build the destination plaintext payload.
	destPayload, err := encodeDestination(destination)
	if err != nil {
		return errors.New("reflex: failed to encode destination").Base(err)
	}

	// 4) Encrypt the destination payload with the PSK.
	psk, err := reflex.DerivePSK(c.userID)
	if err != nil {
		return errors.New("reflex: failed to derive PSK").Base(err)
	}
	pskAEAD, err := chacha20poly1305.New(psk)
	if err != nil {
		return errors.New("reflex: failed to create PSK AEAD").Base(err)
	}
	encPayload := pskAEAD.Seal(nil, pskNonce, destPayload, nil)

	// 5) Write the full handshake packet:
	//    magic(4) + clientPubKey(32) + userID(16) + pskNonce(12) + payloadLen(4) + encPayload
	hsLen := 4 + 32 + 16 + 12 + 4 + len(encPayload)
	hs := make([]byte, hsLen)
	pos := 0
	copy(hs[pos:pos+4], reflex.ReflexMagic())
	pos += 4
	copy(hs[pos:pos+32], clientPubKey[:])
	pos += 32
	copy(hs[pos:pos+16], c.userID[:])
	pos += 16
	copy(hs[pos:pos+12], pskNonce)
	pos += 12
	binary.BigEndian.PutUint32(hs[pos:pos+4], uint32(len(encPayload)))
	pos += 4
	copy(hs[pos:], encPayload)

	if _, err := conn.Write(hs); err != nil {
		return errors.New("reflex: failed to send handshake").Base(err)
	}

	// --- Read server handshake response ---
	// [32 bytes server public key][1 byte status]
	serverResp := make([]byte, 33)
	if _, err := io.ReadFull(conn, serverResp); err != nil {
		return errors.New("reflex: failed to read server handshake").Base(err)
	}
	if serverResp[32] != 0x00 {
		return errors.New("reflex: server rejected the handshake: status=", serverResp[32])
	}

	var serverPubKey [32]byte
	copy(serverPubKey[:], serverResp[0:32])

	// --- Derive session key ---
	sharedSecret, err := reflex.DeriveSharedSecret(clientPrivKey, serverPubKey)
	if err != nil {
		return errors.New("reflex: failed to derive shared secret").Base(err)
	}

	salt := make([]byte, 16+12)
	copy(salt[0:16], c.userID[:])
	copy(salt[16:], pskNonce)
	sessionKey, err := reflex.DeriveSessionKey(sharedSecret, salt)
	if err != nil {
		return errors.New("reflex: failed to derive session key").Base(err)
	}

	// --- Set up the encrypted session ---
	// Client sends DATA → encrypted frames → server
	// Server sends DATA → encrypted frames → client
	frameWriter, err := reflex.NewFrameWriter(conn, sessionKey)
	if err != nil {
		return errors.New("reflex: failed to create frame writer").Base(err)
	}
	frameReader, err := reflex.NewFrameReader(conn, sessionKey)
	if err != nil {
		return errors.New("reflex: failed to create frame reader").Base(err)
	}

	// --- Relay ---
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	// application data → encrypted frames → server
	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		if err := buf.Copy(link.Reader, buf.NewWriter(frameWriter), buf.UpdateActivity(timer)); err != nil {
			return errors.New("reflex: upload ended").Base(err)
		}
		return nil
	}

	// server encrypted frames → application data
	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		if err := buf.Copy(buf.NewReader(frameReader), link.Writer, buf.UpdateActivity(timer)); err != nil {
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
// Helpers
// -------------------------------------------------------------------

// encodeDestination serialises a net.Destination into the binary payload format:
//
//	[1 byte addr type][address bytes][2 bytes port big-endian]
func encodeDestination(dest xnet.Destination) ([]byte, error) {
	addr := dest.Address
	port := uint16(dest.Port)

	var payload []byte
	switch addr.Family() {
	case xnet.AddressFamilyIPv4:
		ip := addr.IP().To4()
		payload = make([]byte, 1+4+2)
		payload[0] = reflex.AddrTypeIPv4
		copy(payload[1:5], ip)
		binary.BigEndian.PutUint16(payload[5:7], port)
	case xnet.AddressFamilyIPv6:
		ip := addr.IP().To16()
		payload = make([]byte, 1+16+2)
		payload[0] = reflex.AddrTypeIPv6
		copy(payload[1:17], ip)
		binary.BigEndian.PutUint16(payload[17:19], port)
	case xnet.AddressFamilyDomain:
		domain := addr.Domain()
		if len(domain) > 255 {
			return nil, errors.New("domain name too long")
		}
		payload = make([]byte, 1+1+len(domain)+2)
		payload[0] = reflex.AddrTypeDomain
		payload[1] = byte(len(domain))
		copy(payload[2:2+len(domain)], domain)
		binary.BigEndian.PutUint16(payload[2+len(domain):], port)
	default:
		return nil, errors.New("unsupported address family: ", addr.Family())
	}
	return payload, nil
}

// parseUUID converts a standard UUID string (with dashes) to a 16-byte array.
func parseUUID(s string) ([16]byte, error) {
	var uid [16]byte
	if len(s) != 36 {
		return uid, errors.New("invalid UUID length")
	}
	src := []byte(s)
	dst := uid[:]
	di := 0
	for si := 0; si < len(src); {
		if src[si] == '-' {
			si++
			continue
		}
		if di >= 16 {
			return uid, errors.New("UUID too long")
		}
		hi := hexVal(src[si])
		lo := hexVal(src[si+1])
		if hi > 15 || lo > 15 {
			return uid, errors.New("invalid hex in UUID")
		}
		dst[di] = hi<<4 | lo
		di++
		si += 2
	}
	return uid, nil
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
