package localization

import (
	"fmt"
	"math"
	"time"
)

// Strategy selects how a failed audit is localized.
type Strategy string

const (
	// StrategyDefault defers to the service's configured strategy (ACHP unless
	// the service was built WithStrategy(StrategyFixedDepth)).
	StrategyDefault Strategy = ""
	// StrategyFixedDepth is the original traversal: build one authenticated
	// reference proof and walk it κ levels per pruning round.
	StrategyFixedDepth Strategy = "FIXED_DEPTH"
	// StrategyACHP is Adaptive Cost-Aware Hierarchical Pruning.
	StrategyACHP Strategy = "ACHP"
)

// ACHPConfig configures Adaptive Cost-Aware Hierarchical Pruning. Nothing here
// affects what is accepted as evidence: pruning and corruption decisions rest
// on authenticated hashes alone. The configuration only steers which frontier
// is retrieved next, so a poor calibration costs time, never correctness.
type ACHPConfig struct {
	// MaxCandidates is K: the most candidate joint frontiers costed per round.
	MaxCandidates int
	// MismatchPrior is p0: the prior probability that a requested leaf is
	// corrupted. It seeds the subtree mismatch estimates until observations
	// (Prior strength below) outweigh it.
	MismatchPrior float64
	// PriorStrength is the weight of p0, in pseudo-leaves, against the leaves
	// actually observed to match or mismatch during this localization.
	PriorStrength float64
	// Costs calibrates the cost model.
	Costs CostCoefficients
	// Now supplies the clock used to calibrate the I/O estimate from observed
	// retrieval time. Nil uses time.Now. A clock that does not advance
	// disables the calibration.
	Now func() time.Time
}

// CostCoefficients calibrate the per-frontier cost estimate
//
//	Ĉ(F) = Ĉ_IO(F) + Ĉ_net(F) + Ĉ_ver(F) + Σ_{u∈F} p̂_u·V̂(u).
//
// They are plain measurements of the deployment (partition read latency, link
// speed, hash throughput) and should be replaced with calibrated values for a
// real cluster; DefaultACHPConfig supplies uncalibrated starting points only.
type CostCoefficients struct {
	// PartitionAccess is the fixed latency of one grouped partition read.
	PartitionAccess time.Duration
	// RowRead is the additional latency per node row a partition read returns.
	RowRead time.Duration
	// Concurrency is the number of partition reads in flight at once.
	Concurrency int
	// NetworkRTT is the latency of one retrieval round trip.
	NetworkRTT time.Duration
	// NetworkBytesPerSecond is the usable bandwidth to the reference store.
	NetworkBytesPerSecond float64
	// NodeWireBytes is the transferred size of one node (hash plus framing).
	NodeWireBytes float64
	// HashCost is the cost of one interior-node hash.
	HashCost time.Duration
	// CompareCost is the cost of authenticating and comparing one node.
	CompareCost time.Duration
	// AdaptationRate in [0,1] is the weight a newly observed retrieval carries
	// when the I/O estimate is re-scaled. Zero disables the calibration.
	AdaptationRate float64
}

// DefaultACHPConfig returns a valid configuration. The cost coefficients are
// order-of-magnitude starting points for a same-region cluster, not
// measurements; calibrate them (or rely on AdaptationRate) for a real
// deployment.
func DefaultACHPConfig() ACHPConfig {
	return ACHPConfig{
		MaxCandidates: 16,
		MismatchPrior: 1e-3,
		PriorStrength: 64,
		Costs: CostCoefficients{
			PartitionAccess:       time.Millisecond,
			RowRead:               5 * time.Microsecond,
			Concurrency:           8,
			NetworkRTT:            500 * time.Microsecond,
			NetworkBytesPerSecond: 125e6,
			NodeWireBytes:         77,
			HashCost:              500 * time.Nanosecond,
			CompareCost:           50 * time.Nanosecond,
			AdaptationRate:        0.5,
		},
	}
}

// Validate rejects configurations that would make the cost model meaningless.
func (config ACHPConfig) Validate() error {
	if config.MaxCandidates < 1 {
		return fmt.Errorf("ACHP: MaxCandidates must be at least 1")
	}
	if !(config.MismatchPrior > 0 && config.MismatchPrior < 1) {
		return fmt.Errorf("ACHP: MismatchPrior must be in (0,1)")
	}
	if !(config.PriorStrength > 0) || math.IsInf(config.PriorStrength, 0) {
		return fmt.Errorf("ACHP: PriorStrength must be positive and finite")
	}
	costs := config.Costs
	if costs.Concurrency < 1 {
		return fmt.Errorf("ACHP: Concurrency must be at least 1")
	}
	if costs.PartitionAccess < 0 || costs.RowRead < 0 || costs.NetworkRTT < 0 ||
		costs.HashCost < 0 || costs.CompareCost < 0 {
		return fmt.Errorf("ACHP: cost coefficients must not be negative")
	}
	if !(costs.NetworkBytesPerSecond > 0) || math.IsInf(costs.NetworkBytesPerSecond, 0) {
		return fmt.Errorf("ACHP: NetworkBytesPerSecond must be positive and finite")
	}
	if costs.NodeWireBytes < 0 || math.IsNaN(costs.NodeWireBytes) || math.IsInf(costs.NodeWireBytes, 0) {
		return fmt.Errorf("ACHP: NodeWireBytes must be finite and not negative")
	}
	if costs.AdaptationRate < 0 || costs.AdaptationRate > 1 || math.IsNaN(costs.AdaptationRate) {
		return fmt.Errorf("ACHP: AdaptationRate must be in [0,1]")
	}
	return nil
}

// Option configures a Service.
type Option func(*Service) error

// WithACHPConfig replaces the ACHP configuration.
func WithACHPConfig(config ACHPConfig) Option {
	return func(service *Service) error {
		if err := config.Validate(); err != nil {
			return err
		}
		service.achp = config
		return nil
	}
}

// WithStrategy sets the strategy used when a request does not name one.
func WithStrategy(strategy Strategy) Option {
	return func(service *Service) error {
		switch strategy {
		case StrategyFixedDepth, StrategyACHP:
			service.strategy = strategy
			return nil
		default:
			return fmt.Errorf("localization: unknown strategy %q", strategy)
		}
	}
}
