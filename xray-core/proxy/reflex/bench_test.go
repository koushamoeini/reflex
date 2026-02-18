package reflex_test

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
)

// ─────────────────────────────────────────────────────────────────────────────
// Helper: discard writer for benchmarks (no I/O overhead)
// ─────────────────────────────────────────────────────────────────────────────

type discardCounter struct{ n int64 }

func (d *discardCounter) Write(p []byte) (int, error) {
	d.n += int64(len(p))
	return len(p), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// BenchmarkWriteFrame – throughput of Session.WriteFrame at 1 KB payload
// ─────────────────────────────────────────────────────────────────────────────

func BenchmarkWriteFrame(b *testing.B) {
	key := make([]byte, 32)
	s, err := reflex.NewSession(key)
	if err != nil {
		b.Fatalf("NewSession: %v", err)
	}
	data := make([]byte, 1024)
	w := &discardCounter{}

	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		_ = s.WriteFrame(w, reflex.FrameTypeData, data)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BenchmarkEncryptionSizes – WriteFrame at various payload sizes
// ─────────────────────────────────────────────────────────────────────────────

func BenchmarkEncryptionSizes(b *testing.B) {
	sizes := []int{64, 256, 1024, 4096, 16384}
	for _, size := range sizes {
		size := size
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			key := make([]byte, 32)
			s, _ := reflex.NewSession(key)
			data := make([]byte, size)
			w := &discardCounter{}
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = s.WriteFrame(w, reflex.FrameTypeData, data)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BenchmarkMemoryAllocation – allocations per WriteFrame call
// ─────────────────────────────────────────────────────────────────────────────

func BenchmarkMemoryAllocation(b *testing.B) {
	key := make([]byte, 32)
	s, _ := reflex.NewSession(key)
	data := make([]byte, 1024)
	w := &discardCounter{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.WriteFrame(w, reflex.FrameTypeData, data)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BenchmarkReadFrame – round-trip through a bytes.Buffer
// ─────────────────────────────────────────────────────────────────────────────

func BenchmarkReadFrame(b *testing.B) {
	key := make([]byte, 32)
	writer, _ := reflex.NewSession(key)
	reader, _ := reflex.NewSession(key)
	data := make([]byte, 1024)

	// Pre-encode b.N frames into a buffer.
	var buf bytes.Buffer
	for i := 0; i < b.N; i++ {
		_ = writer.WriteFrame(&buf, reflex.FrameTypeData, data)
	}

	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		_, _ = reader.ReadFrame(&buf)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BenchmarkKeyExchange – full X25519 + HKDF key derivation
// ─────────────────────────────────────────────────────────────────────────────

func BenchmarkKeyExchange(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		clientPriv, _, _ := reflex.GenerateKeyPair()
		_, serverPub, _ := reflex.GenerateKeyPair()
		shared, _ := reflex.DeriveSharedSecret(clientPriv, serverPub)
		_, _ = reflex.DeriveSessionKey(shared, []byte("bench-salt"))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BenchmarkNonceCache – NonceCache.Check throughput
// ─────────────────────────────────────────────────────────────────────────────

func BenchmarkNonceCacheCheck(b *testing.B) {
	nc := reflex.NewNonceCache()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nc.Check(uint64(i))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BenchmarkFrameWriter – FrameWriter.Write (io.Writer path, auto-split)
// ─────────────────────────────────────────────────────────────────────────────

func BenchmarkFrameWriter(b *testing.B) {
	key := make([]byte, 32)
	w := &discardCounter{}
	fw, _ := reflex.NewFrameWriter(w, key)
	// Data larger than MaxFramePayload to exercise the split path.
	data := make([]byte, reflex.MaxFramePayload+1)

	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = fw.Write(data)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BenchmarkMorphingWriteFrame – WriteFrameWithMorphing overhead
// ─────────────────────────────────────────────────────────────────────────────

func BenchmarkMorphingWriteFrame(b *testing.B) {
	key := make([]byte, 32)
	s, _ := reflex.NewSession(key)
	// Fast profile: zero delay so benchmark measures CPU, not sleep.
	profile := &reflex.TrafficProfile{
		Name:        "bench",
		PacketSizes: []reflex.PacketSizeDist{{Size: 1024, Weight: 1.0}},
		Delays:      []reflex.DelayDist{{Delay: 0, Weight: 1.0}},
	}
	data := make([]byte, 512) // smaller than target → padding exercised
	w := &discardCounter{}

	b.SetBytes(1024) // on-wire target size
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.WriteFrameWithMorphing(w, reflex.FrameTypeData, data, profile)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BenchmarkAddPadding – padding append
// ─────────────────────────────────────────────────────────────────────────────

func BenchmarkAddPadding(b *testing.B) {
	data := make([]byte, 200)
	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = reflex.AddPadding(data, 1400)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BenchmarkKSTest – statistical test performance
// ─────────────────────────────────────────────────────────────────────────────

func BenchmarkKSTest(b *testing.B) {
	s1 := reflex.GenerateMorphedSizes(&reflex.YouTubeProfile, 500)
	s2 := reflex.GenerateMorphedSizes(&reflex.YouTubeProfile, 500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = reflex.KolmogorovSmirnovTest(s1, s2)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BenchmarkReflexVsRaw – compare encrypted frame write vs plain write
// ─────────────────────────────────────────────────────────────────────────────

func BenchmarkComparison(b *testing.B) {
	data := make([]byte, 1024)

	b.Run("Reflex/WriteFrame", func(b *testing.B) {
		s, _ := reflex.NewSession(make([]byte, 32))
		w := &discardCounter{}
		b.SetBytes(int64(len(data)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = s.WriteFrame(w, reflex.FrameTypeData, data)
		}
	})

	b.Run("RawWrite", func(b *testing.B) {
		w := &discardCounter{}
		b.SetBytes(int64(len(data)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = w.Write(data)
		}
	})

	b.Run("Reflex/FrameWriter", func(b *testing.B) {
		fw, _ := reflex.NewFrameWriter(&discardCounter{}, make([]byte, 32))
		b.SetBytes(int64(len(data)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = fw.Write(data)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// BenchmarkHandshakeKeyGen – key pair generation throughput
// ─────────────────────────────────────────────────────────────────────────────

func BenchmarkHandshakeKeyGen(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = reflex.GenerateKeyPair()
	}
}

// Ensure io is used (for io.Pipe in BenchmarkReadFrame via bytes.Buffer redirect).
var _ io.Writer = (*discardCounter)(nil)
