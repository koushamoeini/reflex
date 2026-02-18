package reflex_test

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
)

// FuzzFrameParsing feeds random bytes to Session.ReadFrame and verifies it
// never panics.  Corrupt data should return an error, not crash the process.
//
// Run with:
//
//	go test -fuzz=FuzzFrameParsing -fuzztime=30s ./proxy/reflex/
func FuzzFrameParsing(f *testing.F) {
	// Seed corpus: valid frames so the fuzzer understands the structure.
	key := make([]byte, 32)
	s, _ := reflex.NewSession(key)

	for _, payload := range [][]byte{
		{},
		[]byte("hello"),
		bytes.Repeat([]byte{0xAB}, 64),
	} {
		var buf bytes.Buffer
		_ = s.WriteFrame(&buf, reflex.FrameTypeData, payload)
		f.Add(buf.Bytes())
	}

	// Edge seeds: common protocol byte patterns.
	f.Add([]byte{0x00, 0x00, 0x01})                        // header only, zero length DATA
	f.Add([]byte{0xFF, 0xFF, 0x01, 0xAA, 0xBB})            // huge claimed length
	f.Add([]byte{0x00, 0x01, 0x02, 0xFF})                  // short ciphertext
	f.Add(reflex.ReflexMagic())                            // magic bytes
	f.Add([]byte("POST /api HTTP/1.1\r\nHost: x\r\n\r\n")) // HTTP disguise header
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00})            // TLS ClientHello prefix

	f.Fuzz(func(t *testing.T, data []byte) {
		r, _ := reflex.NewSession(key)
		// Must not panic regardless of input.
		_, _ = r.ReadFrame(bytes.NewReader(data))
	})
}

// FuzzIsReflexHandshake feeds random byte slices to the detection functions.
// They must never panic.
func FuzzIsReflexHandshake(f *testing.F) {
	f.Add(reflex.ReflexMagic())
	f.Add([]byte("POST /api"))
	f.Add([]byte("GET /"))
	f.Add([]byte{})
	f.Add([]byte{0x52})
	f.Add([]byte{0x52, 0x46, 0x58, 0x4C}) // exact magic

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = reflex.IsReflexMagic(data)
		_ = reflex.IsReflexHandshake(data)
		_ = reflex.IsHTTPPostLike(data)
	})
}

// FuzzAddPadding feeds random data and target sizes to AddPadding.
// It must never panic and must always return a slice of at least
// max(len(data), targetSize) bytes with the original prefix intact.
func FuzzAddPadding(f *testing.F) {
	f.Add([]byte("hello"), 20)
	f.Add([]byte{}, 0)
	f.Add([]byte("x"), 1)
	f.Add(bytes.Repeat([]byte{0xFF}, 100), 50)

	f.Fuzz(func(t *testing.T, data []byte, targetSize int) {
		if targetSize < 0 || targetSize > 65536 {
			return // skip unreasonably large targets
		}
		result := reflex.AddPadding(data, targetSize)

		// Must not be shorter than the original data.
		if len(result) < len(data) {
			t.Fatalf("result shorter than input: %d < %d", len(result), len(data))
		}
		// If targetSize > len(data), result must be exactly targetSize.
		if targetSize > len(data) && len(result) != targetSize {
			t.Fatalf("result length %d != targetSize %d", len(result), targetSize)
		}
		// Original prefix must be intact.
		if len(data) > 0 && !bytes.Equal(result[:len(data)], data) {
			t.Fatal("original data prefix was corrupted by padding")
		}
	})
}

// FuzzKolmogorovSmirnov feeds random float64 slices to KolmogorovSmirnovTest.
// It must never panic and must return values in valid ranges.
func FuzzKolmogorovSmirnov(f *testing.F) {
	toFloat := func(b []byte) []float64 {
		out := make([]float64, len(b))
		for i, v := range b {
			out[i] = float64(v)
		}
		return out
	}

	f.Add([]byte{1, 2, 3}, []byte{4, 5, 6})
	f.Add([]byte{}, []byte{1})
	f.Add([]byte{0}, []byte{0})

	f.Fuzz(func(t *testing.T, a, b []byte) {
		if len(a) == 0 || len(b) == 0 {
			return
		}
		s1 := toFloat(a)
		s2 := toFloat(b)
		res := reflex.KolmogorovSmirnovTest(s1, s2)

		if res.Statistic < 0 || res.Statistic > 1.0+1e-9 {
			t.Fatalf("KS statistic out of range [0,1]: %f", res.Statistic)
		}
		if res.PValue < 0 || res.PValue > 1.0+1e-9 {
			t.Fatalf("KS p-value out of range [0,1]: %f", res.PValue)
		}
	})
}

// FuzzNonceCache feeds random uint64 values to NonceCache.Check.
// It must never panic.
func FuzzNonceCache(f *testing.F) {
	f.Add(uint64(0))
	f.Add(uint64(1))
	f.Add(^uint64(0)) // max uint64

	f.Fuzz(func(t *testing.T, nonce uint64) {
		nc := reflex.NewNonceCache()
		first := nc.Check(nonce)
		second := nc.Check(nonce)

		if !first {
			t.Fatal("first presentation of a nonce was rejected")
		}
		if second {
			t.Fatal("second presentation of the same nonce was accepted (replay)")
		}
	})
}
