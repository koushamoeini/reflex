// Package reflex – Traffic Morphing subsystem (Step 5)
//
// Traffic Morphing makes Reflex traffic statistically resemble legitimate
// protocols (YouTube, Zoom, HTTP/2 REST APIs) by controlling:
//   - packet-size distribution  (via GetPacketSize / AddPadding)
//   - inter-packet delay        (via GetDelay)
//
// Both dimensions honour weighted distributions sampled at runtime.
// PADDING_CTRL and TIMING_CTRL frames let the two sides of a session
// coordinate morphing parameters on the fly.
package reflex

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"math"
	mrand "math/rand"
	"sort"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Distribution element types
// ─────────────────────────────────────────────────────────────────────────────

// PacketSizeDist is one bucket in a packet-size weighted distribution.
type PacketSizeDist struct {
	Size   int     // target plaintext bytes for one morphed packet
	Weight float64 // probability weight (need not sum to 1; normalised internally)
}

// DelayDist is one bucket in an inter-packet delay weighted distribution.
type DelayDist struct {
	Delay  time.Duration
	Weight float64
}

// ─────────────────────────────────────────────────────────────────────────────
// TrafficProfile
// ─────────────────────────────────────────────────────────────────────────────

// TrafficProfile describes a statistical traffic signature.
// It is safe for concurrent use by multiple goroutines.
type TrafficProfile struct {
	Name string
	// PacketSizes is the weighted packet-size distribution.
	// Weights need not sum to 1; sampling uses a cumulative approach.
	PacketSizes []PacketSizeDist
	// Delays is the weighted inter-packet delay distribution.
	Delays []DelayDist

	// One-shot overrides set by SetNextPacketSize / SetNextDelay.
	// These are consumed on the next Get call and then cleared.
	mu             sync.Mutex
	nextPacketSize int
	nextDelay      time.Duration
}

// GetPacketSize samples the next target packet size.
// If a one-shot override is set (via SetNextPacketSize), it is returned once
// and then cleared; otherwise the weighted distribution is sampled.
func (p *TrafficProfile) GetPacketSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextPacketSize > 0 {
		sz := p.nextPacketSize
		p.nextPacketSize = 0
		return sz
	}

	return sampleIntDist(p.PacketSizes)
}

// GetDelay samples the next inter-packet delay.
// If a one-shot override is set (via SetNextDelay), it is returned once and
// then cleared; otherwise the weighted distribution is sampled.
func (p *TrafficProfile) GetDelay() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextDelay > 0 {
		d := p.nextDelay
		p.nextDelay = 0
		return d
	}

	return sampleDelayDist(p.Delays)
}

// SetNextPacketSize overrides the next packet-size sample with size.
// The override is consumed by the very next GetPacketSize call.
func (p *TrafficProfile) SetNextPacketSize(size int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextPacketSize = size
}

// SetNextDelay overrides the next delay sample with delay.
// The override is consumed by the very next GetDelay call.
func (p *TrafficProfile) SetNextDelay(delay time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextDelay = delay
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in profiles (based on published traffic-analysis papers)
// ─────────────────────────────────────────────────────────────────────────────

// YouTubeProfile mimics YouTube video-streaming traffic.
// Packet sizes are dominated by near-MTU frames; delays are short.
var YouTubeProfile = TrafficProfile{
	Name: "YouTube",
	PacketSizes: []PacketSizeDist{
		{Size: 1400, Weight: 0.35}, // near-MTU, most common in video segments
		{Size: 1200, Weight: 0.25},
		{Size: 1000, Weight: 0.20},
		{Size: 800, Weight: 0.10},
		{Size: 600, Weight: 0.05},
		{Size: 400, Weight: 0.05},
	},
	Delays: []DelayDist{
		{Delay: 8 * time.Millisecond, Weight: 0.30},
		{Delay: 12 * time.Millisecond, Weight: 0.25},
		{Delay: 16 * time.Millisecond, Weight: 0.20},
		{Delay: 20 * time.Millisecond, Weight: 0.15},
		{Delay: 30 * time.Millisecond, Weight: 0.10},
	},
}

// ZoomProfile mimics Zoom video-conferencing traffic.
// Smaller, more uniform packets; tighter timing cadence.
var ZoomProfile = TrafficProfile{
	Name: "Zoom",
	PacketSizes: []PacketSizeDist{
		{Size: 500, Weight: 0.30},
		{Size: 600, Weight: 0.40},
		{Size: 700, Weight: 0.30},
	},
	Delays: []DelayDist{
		{Delay: 30 * time.Millisecond, Weight: 0.40},
		{Delay: 40 * time.Millisecond, Weight: 0.40},
		{Delay: 50 * time.Millisecond, Weight: 0.20},
	},
}

// HTTP2APIProfile mimics a busy HTTP/2 REST API service.
// Mixed packet sizes; low latency.
var HTTP2APIProfile = TrafficProfile{
	Name: "HTTP/2 API",
	PacketSizes: []PacketSizeDist{
		{Size: 200, Weight: 0.20},
		{Size: 500, Weight: 0.30},
		{Size: 1000, Weight: 0.30},
		{Size: 1500, Weight: 0.20},
	},
	Delays: []DelayDist{
		{Delay: 5 * time.Millisecond, Weight: 0.30},
		{Delay: 10 * time.Millisecond, Weight: 0.40},
		{Delay: 15 * time.Millisecond, Weight: 0.30},
	},
}

// Profiles is the registry of built-in traffic profiles.
var Profiles = map[string]*TrafficProfile{
	"youtube":   &YouTubeProfile,
	"zoom":      &ZoomProfile,
	"http2-api": &HTTP2APIProfile,
}

// ─────────────────────────────────────────────────────────────────────────────
// Padding helper
// ─────────────────────────────────────────────────────────────────────────────

// AddPadding pads data with random bytes so its length equals targetSize.
// If data is already at or beyond targetSize, it is returned unchanged.
// The caller must treat the returned slice as read-only (it may alias data).
func AddPadding(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		return data
	}
	padding := make([]byte, targetSize-len(data))
	// Use crypto/rand for padding so observers cannot distinguish padding from
	// real encrypted content (both look uniformly random).
	if _, err := rand.Read(padding); err != nil {
		// Extremely unlikely; fall back to zeros.
		for i := range padding {
			padding[i] = 0
		}
	}
	return append(data, padding...)
}

// ─────────────────────────────────────────────────────────────────────────────
// Session – morphed write / control-frame methods
// (added here rather than protocol.go to keep the file focused)
// ─────────────────────────────────────────────────────────────────────────────

// WriteFrameWithMorphing encrypts data and writes it as one or more frames,
// padding each chunk to the target size chosen by profile.GetPacketSize().
//
// If data is larger than the chosen target, it is split recursively until
// all bytes are sent.  After each chunk a delay of profile.GetDelay() is
// applied so the inter-packet timing matches the profile.
func (s *Session) WriteFrameWithMorphing(w io.Writer, frameType byte, data []byte, profile *TrafficProfile) error {
	targetSize := profile.GetPacketSize()

	// If the payload exceeds the target chunk size, split and recurse.
	if len(data) > targetSize {
		if err := s.writeFrameChunk(w, frameType, data[:targetSize], profile); err != nil {
			return err
		}
		return s.WriteFrameWithMorphing(w, frameType, data[targetSize:], profile)
	}

	// Pad the chunk up to targetSize so on-wire size matches the profile.
	morphed := AddPadding(data, targetSize)
	if err := s.WriteFrame(w, frameType, morphed); err != nil {
		return err
	}

	// Apply the profile's inter-packet delay after writing each chunk.
	delay := profile.GetDelay()
	if delay > 0 {
		time.Sleep(delay)
	}
	return nil
}

// writeFrameChunk is a thin shim so the recursion in WriteFrameWithMorphing
// reads cleanly.
func (s *Session) writeFrameChunk(w io.Writer, frameType byte, data []byte, profile *TrafficProfile) error {
	return s.WriteFrameWithMorphing(w, frameType, data, profile)
}

// SendPaddingControl sends a PADDING_CTRL frame instructing the remote side to
// use targetSize as its next packet size (one-shot override).
func (s *Session) SendPaddingControl(w io.Writer, targetSize int) error {
	ctrlData := make([]byte, 2)
	binary.BigEndian.PutUint16(ctrlData, uint16(targetSize))
	return s.WriteFrame(w, FrameTypePadding, ctrlData)
}

// SendTimingControl sends a TIMING_CTRL frame instructing the remote side to
// apply delay as its next inter-packet delay (one-shot override).
func (s *Session) SendTimingControl(w io.Writer, delay time.Duration) error {
	ctrlData := make([]byte, 8)
	binary.BigEndian.PutUint64(ctrlData, uint64(delay.Milliseconds()))
	return s.WriteFrame(w, FrameTypeTiming, ctrlData)
}

// HandleControlFrame processes a PADDING_CTRL or TIMING_CTRL frame received
// from the remote peer and applies the requested override to profile.
// Other frame types are silently ignored.
func (s *Session) HandleControlFrame(frame *Frame, profile *TrafficProfile) {
	switch frame.Type {
	case FrameTypePadding:
		if len(frame.Payload) >= 2 {
			targetSize := int(binary.BigEndian.Uint16(frame.Payload))
			profile.SetNextPacketSize(targetSize)
		}
	case FrameTypeTiming:
		if len(frame.Payload) >= 8 {
			delayMs := binary.BigEndian.Uint64(frame.Payload)
			profile.SetNextDelay(time.Duration(delayMs) * time.Millisecond)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Profile construction from capture data
// ─────────────────────────────────────────────────────────────────────────────

// CreateProfileFromCapture builds a TrafficProfile from raw measurements
// obtained from a real traffic capture (e.g., via tshark or Wireshark).
func CreateProfileFromCapture(name string, packetSizes []int, delays []time.Duration) *TrafficProfile {
	return &TrafficProfile{
		Name:        name,
		PacketSizes: CalculateSizeDistribution(packetSizes),
		Delays:      CalculateDelayDistribution(delays),
	}
}

// CalculateSizeDistribution converts a slice of observed packet sizes into a
// weighted distribution sorted in ascending size order.
func CalculateSizeDistribution(values []int) []PacketSizeDist {
	if len(values) == 0 {
		return nil
	}
	freq := make(map[int]int, len(values))
	for _, v := range values {
		freq[v]++
	}
	total := float64(len(values))
	dist := make([]PacketSizeDist, 0, len(freq))
	for size, count := range freq {
		dist = append(dist, PacketSizeDist{
			Size:   size,
			Weight: float64(count) / total,
		})
	}
	sort.Slice(dist, func(i, j int) bool { return dist[i].Size < dist[j].Size })
	return dist
}

// CalculateDelayDistribution converts a slice of observed inter-packet delays
// into a weighted distribution sorted in ascending delay order.
func CalculateDelayDistribution(values []time.Duration) []DelayDist {
	if len(values) == 0 {
		return nil
	}
	freq := make(map[time.Duration]int, len(values))
	for _, v := range values {
		freq[v]++
	}
	total := float64(len(values))
	dist := make([]DelayDist, 0, len(freq))
	for delay, count := range freq {
		dist = append(dist, DelayDist{
			Delay:  delay,
			Weight: float64(count) / total,
		})
	}
	sort.Slice(dist, func(i, j int) bool { return dist[i].Delay < dist[j].Delay })
	return dist
}

// ─────────────────────────────────────────────────────────────────────────────
// Statistical validation – Kolmogorov-Smirnov test
// ─────────────────────────────────────────────────────────────────────────────

// KSTestResult holds the result of a two-sample Kolmogorov-Smirnov test.
type KSTestResult struct {
	// Statistic is the KS statistic D = max |F1(x) - F2(x)|.
	Statistic float64
	// PValue is the asymptotic p-value.  PValue > 0.05 means the two samples
	// are not statistically distinguishable at the 95% confidence level.
	PValue float64
}

// KolmogorovSmirnovTest performs a two-sample KS test on sample1 and sample2.
// It returns the test statistic D and an asymptotic p-value.
//
// This lets callers verify that morph-generated traffic is statistically
// indistinguishable from a reference (e.g., real YouTube packet capture).
func KolmogorovSmirnovTest(sample1, sample2 []float64) KSTestResult {
	if len(sample1) == 0 || len(sample2) == 0 {
		return KSTestResult{}
	}

	s1 := make([]float64, len(sample1))
	copy(s1, sample1)
	s2 := make([]float64, len(sample2))
	copy(s2, sample2)
	sort.Float64s(s1)
	sort.Float64s(s2)

	n1 := float64(len(s1))
	n2 := float64(len(s2))

	// Walk both sorted arrays and compute the maximum CDF gap.
	d := 0.0
	i, j := 0, 0
	for i < len(s1) && j < len(s2) {
		// Advance past equal values in each sample.
		x := s1[i]
		if s2[j] < x {
			x = s2[j]
		}
		for i < len(s1) && s1[i] <= x {
			i++
		}
		for j < len(s2) && s2[j] <= x {
			j++
		}
		gap := absFloat(float64(i)/n1 - float64(j)/n2)
		if gap > d {
			d = gap
		}
	}

	// Asymptotic p-value using the Kolmogorov distribution.
	// p = 2 * Σ_{k=1}^{∞} (-1)^{k-1} exp(-2k²λ²)  where λ = D * sqrt(n1*n2/(n1+n2))
	lambda := d * math.Sqrt((n1*n2)/(n1+n2))
	pValue := ksProb(lambda)

	return KSTestResult{Statistic: d, PValue: pValue}
}

// GenerateMorphedSizes returns n packet sizes drawn from profile.
// Delays are not sampled (they are applied asynchronously during real writes).
// This helper exists for statistical testing without touching the network.
func GenerateMorphedSizes(profile *TrafficProfile, n int) []float64 {
	out := make([]float64, n)
	for i := range out {
		out[i] = float64(profile.GetPacketSize())
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

// sampleIntDist samples one integer from a weighted distribution.
// The weights need not sum to 1; they are treated as relative probabilities.
func sampleIntDist(dist []PacketSizeDist) int {
	if len(dist) == 0 {
		return 0
	}
	// Compute weight sum for normalisation.
	total := 0.0
	for _, d := range dist {
		total += d.Weight
	}
	r := mrand.Float64() * total
	cumsum := 0.0
	for _, d := range dist {
		cumsum += d.Weight
		if r <= cumsum {
			return d.Size
		}
	}
	return dist[len(dist)-1].Size
}

// sampleDelayDist samples one delay from a weighted distribution.
func sampleDelayDist(dist []DelayDist) time.Duration {
	if len(dist) == 0 {
		return 0
	}
	total := 0.0
	for _, d := range dist {
		total += d.Weight
	}
	r := mrand.Float64() * total
	cumsum := 0.0
	for _, d := range dist {
		cumsum += d.Weight
		if r <= cumsum {
			return d.Delay
		}
	}
	return dist[len(dist)-1].Delay
}

// absFloat returns the absolute value of f.
func absFloat(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

// ksProb computes the asymptotic KS p-value for the given lambda.
// p = 2 * Σ_{k=1}^∞ (-1)^{k-1} exp(-2 k² λ²)
func ksProb(lambda float64) float64 {
	if lambda <= 0 {
		return 1.0
	}
	p := 0.0
	for k := 1; k <= 100; k++ {
		sign := 1.0
		if k%2 == 0 {
			sign = -1.0
		}
		term := sign * math.Exp(-2.0*float64(k)*float64(k)*lambda*lambda)
		p += term
		if absFloat(term) < 1e-10 {
			break
		}
	}
	p *= 2.0
	if p < 0 {
		p = 0
	}
	if p > 1 {
		p = 1
	}
	return p
}
