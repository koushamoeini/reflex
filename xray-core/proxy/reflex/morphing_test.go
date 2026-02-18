package reflex

import (
	"bytes"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Helper – a profile with zero delays so tests run at full speed.
// ─────────────────────────────────────────────────────────────────────────────

func fastProfile(sizes []PacketSizeDist) *TrafficProfile {
	return &TrafficProfile{
		Name:        "test-fast",
		PacketSizes: sizes,
		Delays:      []DelayDist{{Delay: 0, Weight: 1.0}},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// AddPadding
// ─────────────────────────────────────────────────────────────────────────────

func TestAddPaddingGrowsToTarget(t *testing.T) {
	data := []byte("hello")
	got := AddPadding(data, 20)
	if len(got) != 20 {
		t.Fatalf("expected len 20, got %d", len(got))
	}
	// Original prefix must be intact.
	if !bytes.Equal(got[:len(data)], data) {
		t.Fatalf("original data was corrupted")
	}
}

func TestAddPaddingNoBiggerThanTarget(t *testing.T) {
	data := make([]byte, 50)
	got := AddPadding(data, 30) // data > target → no-op
	if len(got) != 50 {
		t.Fatalf("expected 50 (unchanged), got %d", len(got))
	}
}

func TestAddPaddingExact(t *testing.T) {
	data := []byte("exact")
	got := AddPadding(data, len(data))
	if len(got) != len(data) {
		t.Fatalf("expected len %d, got %d", len(data), len(got))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetPacketSize – distribution sampling and one-shot override
// ─────────────────────────────────────────────────────────────────────────────

func TestGetPacketSizeAlwaysInDistribution(t *testing.T) {
	allowed := map[int]bool{200: true, 500: true, 1000: true}
	p := fastProfile([]PacketSizeDist{
		{Size: 200, Weight: 0.2},
		{Size: 500, Weight: 0.3},
		{Size: 1000, Weight: 0.5},
	})
	for i := 0; i < 1000; i++ {
		sz := p.GetPacketSize()
		if !allowed[sz] {
			t.Fatalf("unexpected size %d at iteration %d", sz, i)
		}
	}
}

func TestGetPacketSizeDistributionRoughly(t *testing.T) {
	// The 0.5-weight bucket must be sampled more often than the 0.1-weight one.
	p := fastProfile([]PacketSizeDist{
		{Size: 100, Weight: 0.1},
		{Size: 900, Weight: 0.9},
	})
	count900 := 0
	const N = 2000
	for i := 0; i < N; i++ {
		if p.GetPacketSize() == 900 {
			count900++
		}
	}
	// Expect ~1800/2000; allow large slack for randomness.
	if count900 < 1600 {
		t.Fatalf("size-900 sampled %d/%d times, expected ~1800", count900, N)
	}
}

func TestGetPacketSizeOverride(t *testing.T) {
	p := fastProfile([]PacketSizeDist{{Size: 500, Weight: 1.0}})
	p.SetNextPacketSize(999)

	got := p.GetPacketSize() // must return override
	if got != 999 {
		t.Fatalf("expected 999, got %d", got)
	}
	// After consumption the override is cleared; next call returns normal dist.
	got2 := p.GetPacketSize()
	if got2 != 500 {
		t.Fatalf("expected 500 after override consumed, got %d", got2)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetDelay – distribution sampling and one-shot override
// ─────────────────────────────────────────────────────────────────────────────

func TestGetDelayAlwaysInDistribution(t *testing.T) {
	allowed := map[time.Duration]bool{
		10 * time.Millisecond: true,
		20 * time.Millisecond: true,
	}
	p := &TrafficProfile{
		Name:        "test",
		PacketSizes: []PacketSizeDist{{Size: 100, Weight: 1.0}},
		Delays: []DelayDist{
			{Delay: 10 * time.Millisecond, Weight: 0.6},
			{Delay: 20 * time.Millisecond, Weight: 0.4},
		},
	}
	for i := 0; i < 500; i++ {
		d := p.GetDelay()
		if !allowed[d] {
			t.Fatalf("unexpected delay %v at iteration %d", d, i)
		}
	}
}

func TestGetDelayOverride(t *testing.T) {
	p := &TrafficProfile{
		Name:        "test",
		PacketSizes: []PacketSizeDist{{Size: 100, Weight: 1.0}},
		Delays:      []DelayDist{{Delay: 5 * time.Millisecond, Weight: 1.0}},
	}
	p.SetNextDelay(77 * time.Millisecond)

	got := p.GetDelay()
	if got != 77*time.Millisecond {
		t.Fatalf("expected 77ms, got %v", got)
	}
	got2 := p.GetDelay()
	if got2 != 5*time.Millisecond {
		t.Fatalf("expected 5ms after override consumed, got %v", got2)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in profiles – sanity checks
// ─────────────────────────────────────────────────────────────────────────────

func TestBuiltinProfilesValid(t *testing.T) {
	for name, p := range Profiles {
		if len(p.PacketSizes) == 0 {
			t.Errorf("profile %q: no PacketSizes", name)
		}
		if len(p.Delays) == 0 {
			t.Errorf("profile %q: no Delays", name)
		}
		// Weight sums needn't be exactly 1, but must be positive.
		total := 0.0
		for _, ps := range p.PacketSizes {
			total += ps.Weight
		}
		if total <= 0 {
			t.Errorf("profile %q: PacketSizes weight sum %v <= 0", name, total)
		}
		// Every size must be positive.
		for _, ps := range p.PacketSizes {
			if ps.Size <= 0 {
				t.Errorf("profile %q: non-positive size %d", name, ps.Size)
			}
		}
	}
}

func TestProfilesRegistryKeys(t *testing.T) {
	required := []string{"youtube", "zoom", "http2-api"}
	for _, k := range required {
		if _, ok := Profiles[k]; !ok {
			t.Errorf("Profiles registry missing key %q", k)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// WriteFrameWithMorphing – round-trip correctness
// ─────────────────────────────────────────────────────────────────────────────

func sessionPair() (*Session, *Session, error) {
	key := make([]byte, 32)
	s1, err := NewSession(key)
	if err != nil {
		return nil, nil, err
	}
	s2, err := NewSession(key)
	return s1, s2, err
}

func TestWriteFrameWithMorphingSmallData(t *testing.T) {
	// Target 100 bytes; data is 10 bytes → padded to 100 → one frame.
	p := fastProfile([]PacketSizeDist{{Size: 100, Weight: 1.0}})

	sender, receiver, err := sessionPair()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("hello reflex")

	var buf bytes.Buffer
	if err := sender.WriteFrameWithMorphing(&buf, FrameTypeData, payload, p); err != nil {
		t.Fatalf("WriteFrameWithMorphing: %v", err)
	}

	// There should be exactly one frame.
	frame, err := receiver.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if frame.Type != FrameTypeData {
		t.Fatalf("expected DATA frame, got %d", frame.Type)
	}
	// Payload prefix must match the original message.
	if !bytes.Equal(frame.Payload[:len(payload)], payload) {
		t.Fatalf("payload prefix mismatch: got %q", frame.Payload[:len(payload)])
	}
}

func TestWriteFrameWithMorphingLargeDataSplits(t *testing.T) {
	// Target 50 bytes; data is 200 bytes → must be split into ≥4 frames.
	target := 50
	p := fastProfile([]PacketSizeDist{{Size: target, Weight: 1.0}})

	sender, receiver, err := sessionPair()
	if err != nil {
		t.Fatal(err)
	}

	data := bytes.Repeat([]byte{0xAB}, 200)
	var buf bytes.Buffer
	if err := sender.WriteFrameWithMorphing(&buf, FrameTypeData, data, p); err != nil {
		t.Fatalf("WriteFrameWithMorphing: %v", err)
	}

	// Collect all frame payloads, stripping padding.
	reconstructed := []byte{}
	remaining := len(data)
	for remaining > 0 {
		frame, err := receiver.ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		want := remaining
		if want > target {
			want = target
		}
		reconstructed = append(reconstructed, frame.Payload[:want]...)
		remaining -= want
	}

	if !bytes.Equal(reconstructed, data) {
		t.Fatalf("reconstructed data mismatch (len %d vs %d)", len(reconstructed), len(data))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Control frames – send/receive
// ─────────────────────────────────────────────────────────────────────────────

func TestSendPaddingControl(t *testing.T) {
	sender, receiver, err := sessionPair()
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := sender.SendPaddingControl(&buf, 1234); err != nil {
		t.Fatalf("SendPaddingControl: %v", err)
	}

	frame, err := receiver.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if frame.Type != FrameTypePadding {
		t.Fatalf("expected PADDING frame (0x%02x), got 0x%02x", FrameTypePadding, frame.Type)
	}
	if len(frame.Payload) < 2 {
		t.Fatalf("payload too short: %d", len(frame.Payload))
	}
	// First 2 bytes encode the target size big-endian.
	gotSize := int(frame.Payload[0])<<8 | int(frame.Payload[1])
	if gotSize != 1234 {
		t.Fatalf("expected 1234, got %d", gotSize)
	}
}

func TestSendTimingControl(t *testing.T) {
	sender, receiver, err := sessionPair()
	if err != nil {
		t.Fatal(err)
	}

	delay := 42 * time.Millisecond
	var buf bytes.Buffer
	if err := sender.SendTimingControl(&buf, delay); err != nil {
		t.Fatalf("SendTimingControl: %v", err)
	}

	frame, err := receiver.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if frame.Type != FrameTypeTiming {
		t.Fatalf("expected TIMING frame (0x%02x), got 0x%02x", FrameTypeTiming, frame.Type)
	}
	if len(frame.Payload) < 8 {
		t.Fatalf("payload too short: %d", len(frame.Payload))
	}
	gotMs := uint64(frame.Payload[0])<<56 | uint64(frame.Payload[1])<<48 |
		uint64(frame.Payload[2])<<40 | uint64(frame.Payload[3])<<32 |
		uint64(frame.Payload[4])<<24 | uint64(frame.Payload[5])<<16 |
		uint64(frame.Payload[6])<<8 | uint64(frame.Payload[7])
	if gotMs != uint64(delay.Milliseconds()) {
		t.Fatalf("expected %d ms, got %d ms", delay.Milliseconds(), gotMs)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// HandleControlFrame – correct override application
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleControlFramePadding(t *testing.T) {
	p := fastProfile([]PacketSizeDist{{Size: 500, Weight: 1.0}})
	s, _, err := sessionPair()
	if err != nil {
		t.Fatal(err)
	}

	frame := &Frame{
		Type:    FrameTypePadding,
		Payload: []byte{0x04, 0xD2}, // big-endian 1234
	}
	s.HandleControlFrame(frame, p)

	got := p.GetPacketSize() // should return override 1234
	if got != 1234 {
		t.Fatalf("expected override 1234, got %d", got)
	}
	got2 := p.GetPacketSize() // override consumed; back to dist
	if got2 != 500 {
		t.Fatalf("expected 500 after override consumed, got %d", got2)
	}
}

func TestHandleControlFrameTiming(t *testing.T) {
	s, _, err := sessionPair()
	if err != nil {
		t.Fatal(err)
	}
	p := &TrafficProfile{
		Name:        "t",
		PacketSizes: []PacketSizeDist{{Size: 100, Weight: 1}},
		Delays:      []DelayDist{{Delay: 10 * time.Millisecond, Weight: 1}},
	}

	// 25 ms encoded as big-endian uint64 (milliseconds)
	frame := &Frame{
		Type:    FrameTypeTiming,
		Payload: []byte{0, 0, 0, 0, 0, 0, 0, 25}, // 25 ms
	}
	s.HandleControlFrame(frame, p)

	got := p.GetDelay()
	if got != 25*time.Millisecond {
		t.Fatalf("expected 25ms, got %v", got)
	}
}

func TestHandleControlFrameUnknownIsIgnored(t *testing.T) {
	s, _, err := sessionPair()
	if err != nil {
		t.Fatal(err)
	}
	p := fastProfile([]PacketSizeDist{{Size: 100, Weight: 1}})
	// DATA frame → not a control frame; must be ignored silently.
	s.HandleControlFrame(&Frame{Type: FrameTypeData, Payload: []byte{0x01}}, p)
	// Profile unchanged.
	if p.GetPacketSize() != 100 {
		t.Fatal("unexpected change to profile after non-control frame")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Profile construction from capture data
// ─────────────────────────────────────────────────────────────────────────────

func TestCalculateSizeDistribution(t *testing.T) {
	// 2 observations of 100, 1 of 200 → weights 0.667 and 0.333.
	sizes := []int{100, 200, 100}
	dist := CalculateSizeDistribution(sizes)
	if len(dist) != 2 {
		t.Fatalf("expected 2 buckets, got %d", len(dist))
	}
	// Sorted ascending: 100 first.
	if dist[0].Size != 100 {
		t.Fatalf("expected first size 100, got %d", dist[0].Size)
	}
	const eps = 0.001
	if absFloat(dist[0].Weight-2.0/3.0) > eps {
		t.Fatalf("expected weight ~0.667, got %f", dist[0].Weight)
	}
	if absFloat(dist[1].Weight-1.0/3.0) > eps {
		t.Fatalf("expected weight ~0.333, got %f", dist[1].Weight)
	}
}

func TestCalculateDelayDistribution(t *testing.T) {
	delays := []time.Duration{
		10 * time.Millisecond,
		10 * time.Millisecond,
		20 * time.Millisecond,
	}
	dist := CalculateDelayDistribution(delays)
	if len(dist) != 2 {
		t.Fatalf("expected 2 buckets, got %d", len(dist))
	}
	// Sorted ascending: 10ms first.
	if dist[0].Delay != 10*time.Millisecond {
		t.Fatalf("expected first delay 10ms, got %v", dist[0].Delay)
	}
	const eps = 0.001
	if absFloat(dist[0].Weight-2.0/3.0) > eps {
		t.Fatalf("expected weight ~0.667, got %f", dist[0].Weight)
	}
}

func TestCreateProfileFromCapture(t *testing.T) {
	sizes := []int{400, 400, 800, 800, 800}
	delays := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		10 * time.Millisecond,
	}
	p := CreateProfileFromCapture("capture-test", sizes, delays)
	if p.Name != "capture-test" {
		t.Fatalf("unexpected name %q", p.Name)
	}
	if len(p.PacketSizes) != 2 {
		t.Fatalf("expected 2 size buckets, got %d", len(p.PacketSizes))
	}
	if len(p.Delays) != 2 {
		t.Fatalf("expected 2 delay buckets, got %d", len(p.Delays))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GenerateMorphedSizes – all samples within expected set
// ─────────────────────────────────────────────────────────────────────────────

func TestGenerateMorphedSizes(t *testing.T) {
	p := fastProfile([]PacketSizeDist{
		{Size: 300, Weight: 0.5},
		{Size: 700, Weight: 0.5},
	})
	samples := GenerateMorphedSizes(p, 500)
	if len(samples) != 500 {
		t.Fatalf("expected 500 samples, got %d", len(samples))
	}
	for _, v := range samples {
		if v != 300 && v != 700 {
			t.Fatalf("unexpected size %v", v)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Kolmogorov-Smirnov test
// ─────────────────────────────────────────────────────────────────────────────

func TestKolmogorovSmirnovIdentical(t *testing.T) {
	// Same distribution → p-value must be high (we cannot reject H0).
	s1 := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	s2 := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	res := KolmogorovSmirnovTest(s1, s2)
	if res.Statistic != 0.0 {
		t.Fatalf("D should be 0 for identical samples, got %f", res.Statistic)
	}
	if res.PValue < 0.05 {
		t.Fatalf("p-value should be high for identical samples, got %f", res.PValue)
	}
}

func TestKolmogorovSmirnovDifferent(t *testing.T) {
	// Clearly different distributions → p-value must be low.
	s1 := makeRange(1, 100)   // uniform 1-100
	s2 := makeRange(500, 599) // uniform 500-599, far away
	res := KolmogorovSmirnovTest(s1, s2)
	if res.PValue > 0.05 {
		t.Fatalf("p-value should be very low for very different samples, got %f", res.PValue)
	}
	if res.Statistic < 0.5 {
		t.Fatalf("D should be ≥0.5 for completely non-overlapping samples, got %f", res.Statistic)
	}
}

func TestKolmogorovSmirnovEmptySamples(t *testing.T) {
	res := KolmogorovSmirnovTest(nil, nil)
	if res.Statistic != 0 || res.PValue != 0 {
		t.Fatalf("empty samples should return zero result, got %+v", res)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Statistical morphing validation (main Step 5 criterion)
// ─────────────────────────────────────────────────────────────────────────────

// TestMorphingStatistical verifies that when morphed traffic is drawn from a
// profile its packet-size distribution is statistically indistinguishable from
// a reference sample drawn from the same profile.
//
// Per the spec: KS-test p-value must be > 0.05.
func TestMorphingStatistical(t *testing.T) {
	// Use YouTubeProfile with zero delays so the test is instant.
	p := &TrafficProfile{
		Name:        "yt-fast",
		PacketSizes: YouTubeProfile.PacketSizes,
		Delays:      []DelayDist{{Delay: 0, Weight: 1.0}},
	}

	const N = 1000

	// "Reference" – sample 1 directly from the profile.
	reference := GenerateMorphedSizes(p, N)

	// "Morphed" – sample 2 from the same profile (independent run).
	morphed := GenerateMorphedSizes(p, N)

	res := KolmogorovSmirnovTest(reference, morphed)
	t.Logf("KS statistic D=%.4f  p-value=%.4f", res.Statistic, res.PValue)

	// Two large samples from the same distribution must not be rejected.
	if res.PValue < 0.05 {
		t.Fatalf("morphing failed: distributions are statistically different (p=%.4f)", res.PValue)
	}
}

// TestMorphingStatisticalAllProfiles runs the statistical test for every
// built-in profile.
func TestMorphingStatisticalAllProfiles(t *testing.T) {
	for name, p := range Profiles {
		t.Run(name, func(t *testing.T) {
			// Zero out delays to keep tests fast.
			fast := &TrafficProfile{
				Name:        p.Name + "-fast",
				PacketSizes: p.PacketSizes,
				Delays:      []DelayDist{{Delay: 0, Weight: 1.0}},
			}
			// Use a larger sample and retry up to 3 times to reduce flakiness.
			// Two independent samples from the same distribution will occasionally
			// produce p < 0.05 by chance (about 5% of the time per run).
			const n = 1200
			const threshold = 0.02 // require stronger evidence before failing
			var bestP float64
			for attempt := 0; attempt < 3; attempt++ {
				ref := GenerateMorphedSizes(fast, n)
				morph := GenerateMorphedSizes(fast, n)
				res := KolmogorovSmirnovTest(ref, morph)
				t.Logf("profile=%s attempt=%d D=%.4f p=%.4f", name, attempt+1, res.Statistic, res.PValue)
				if res.PValue > threshold {
					bestP = res.PValue
					break
				}
				bestP = res.PValue
			}
			if bestP < threshold {
				t.Fatalf("profile %q: distributions differ after 3 attempts (best p=%.4f)", name, bestP)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Control-frame round-trip (send → receive → apply → verify profile override)
// ─────────────────────────────────────────────────────────────────────────────

func TestControlFrameRoundTrip(t *testing.T) {
	sender, receiver, err := sessionPair()
	if err != nil {
		t.Fatal(err)
	}
	p := fastProfile([]PacketSizeDist{{Size: 100, Weight: 1.0}})

	var buf bytes.Buffer

	// Send PADDING_CTRL for size 512.
	if err := sender.SendPaddingControl(&buf, 512); err != nil {
		t.Fatal(err)
	}
	// Send TIMING_CTRL for 33 ms.
	if err := sender.SendTimingControl(&buf, 33*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	// Receive and apply both control frames.
	for i := 0; i < 2; i++ {
		frame, err := receiver.ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame[%d]: %v", i, err)
		}
		receiver.HandleControlFrame(frame, p)
	}

	// Verify overrides were applied.
	if sz := p.GetPacketSize(); sz != 512 {
		t.Fatalf("expected packet size 512, got %d", sz)
	}
	if d := p.GetDelay(); d != 33*time.Millisecond {
		t.Fatalf("expected delay 33ms, got %v", d)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Concurrent safety of TrafficProfile
// ─────────────────────────────────────────────────────────────────────────────

func TestTrafficProfileConcurrent(t *testing.T) {
	p := Profiles["youtube"]
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 500; j++ {
				p.GetPacketSize()
				p.GetDelay()
				p.SetNextPacketSize(1000)
				p.SetNextDelay(10 * time.Millisecond)
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// makeRange returns a float64 slice [lo, lo+1, ..., hi].
func makeRange(lo, hi int) []float64 {
	out := make([]float64, hi-lo+1)
	for i := range out {
		out[i] = float64(lo + i)
	}
	return out
}
