package exp2b

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"

	"github.com/SirojWongpitakroj/hmf-audit/internal/localization"
)

// Output layout, relative to the Experiment 2B directory:
//
//	manifests/queries.json
//	manifests/corruption.json
//	results/raw.csv
//	results/summary.csv
//	results/run_config.json
const (
	QueriesFile    = "manifests/queries.json"
	CorruptionFile = "manifests/corruption.json"
	RawFile        = "results/raw.csv"
	SummaryFile    = "results/summary.csv"
	RunConfigFile  = "results/run_config.json"
)

// WriteJSON writes an indented JSON file, creating its directory.
func WriteJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(encoded, '\n'), 0o644)
}

func readJSON(path string, value any) error {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, value)
}

// LoadOrGenerate returns the persisted manifests under dir, or draws and
// persists them when none exist. Persisted manifests are validated against the
// layout and the requested parameters and are never silently regenerated: a
// mismatch is an error, so the query sets stay fixed for the whole experiment.
func LoadOrGenerate(dir string, params Params, layout *Layout) (QueryManifest, CorruptionManifest, bool, error) {
	queriesPath, corruptionPath := filepath.Join(dir, QueriesFile), filepath.Join(dir, CorruptionFile)
	var queries QueryManifest
	var corruption CorruptionManifest
	queriesErr, corruptionErr := readJSON(queriesPath, &queries), readJSON(corruptionPath, &corruption)
	switch {
	case queriesErr == nil && corruptionErr == nil:
		if !reflect.DeepEqual(queries.Params, params) {
			return queries, corruption, false, fmt.Errorf(
				"exp2b: the manifests in %s were drawn with different parameters (%+v, requested %+v); "+
					"remove them deliberately to start a new experiment", dir, queries.Params, params)
		}
		if err := ValidateQueries(queries, layout); err != nil {
			return queries, corruption, false, err
		}
		if err := ValidateCorruption(queries, corruption, layout); err != nil {
			return queries, corruption, false, err
		}
		return queries, corruption, false, nil
	case errors.Is(queriesErr, fs.ErrNotExist) && errors.Is(corruptionErr, fs.ErrNotExist):
	default:
		return queries, corruption, false, fmt.Errorf("exp2b: read manifests in %s: queries: %v, corruption: %v",
			dir, queriesErr, corruptionErr)
	}
	queries, err := GenerateQueries(params, layout)
	if err != nil {
		return queries, corruption, false, err
	}
	corruption, err = GenerateCorruption(queries, layout)
	if err != nil {
		return queries, corruption, false, err
	}
	if err := WriteJSON(queriesPath, queries); err != nil {
		return queries, corruption, false, err
	}
	if err := WriteJSON(corruptionPath, corruption); err != nil {
		return queries, corruption, false, err
	}
	return queries, corruption, true, nil
}

// ACHPCoefficients records the cost model the ACHP runs used.
type ACHPCoefficients struct {
	MaxCandidates         int     `json:"max_candidates"`
	MismatchPrior         float64 `json:"mismatch_prior"`
	PriorStrength         float64 `json:"prior_strength"`
	PartitionAccessSec    float64 `json:"partition_access_seconds"`
	RowReadSec            float64 `json:"row_read_seconds"`
	Concurrency           int     `json:"concurrency"`
	NetworkRTTSec         float64 `json:"network_rtt_seconds"`
	NetworkBytesPerSecond float64 `json:"network_bytes_per_second"`
	NodeWireBytes         float64 `json:"node_wire_bytes"`
	HashCostSec           float64 `json:"hash_cost_seconds"`
	CompareCostSec        float64 `json:"compare_cost_seconds"`
	AdaptationRate        float64 `json:"adaptation_rate"`
}

// RunConfig is results/run_config.json: everything needed to interpret and
// repeat the run.
type RunConfig struct {
	Experiment       string            `json:"experiment"`
	Mode             string            `json:"mode"` // "cloud" or "in-memory"
	GitCommit        string            `json:"git_commit"`
	GoVersion        string            `json:"go_version"`
	GOMAXPROCS       int               `json:"gomaxprocs"`
	StartedAt        string            `json:"started_at"`
	Params           Params            `json:"params"`
	Algorithms       []string          `json:"algorithms"`
	Excluded         []string          `json:"excluded_algorithms,omitempty"`
	ExcludedReason   string            `json:"excluded_reason,omitempty"`
	FixedKappa       int32             `json:"fixed_depth_kappa_effective"`
	FixedKappaWanted int32             `json:"fixed_depth_kappa_requested"`
	KappaNote        string            `json:"kappa_note,omitempty"`
	ACHP             ACHPCoefficients  `json:"achp"`
	HPPConcurrency   int               `json:"hpp_concurrency"`
	VerifyProofs     bool              `json:"verify_proofs"`
	LayoutSHA256     string            `json:"layout_sha256"`
	QueriesSHA256    string            `json:"queries_sha256"`
	Dataset          string            `json:"dataset,omitempty"`
	Environment      map[string]string `json:"environment,omitempty"`
	Notes            []string          `json:"notes,omitempty"`
}

// CoefficientsOf records an ACHP configuration for run_config.json.
func CoefficientsOf(config localization.ACHPConfig) ACHPCoefficients {
	costs := config.Costs
	return ACHPCoefficients{
		MaxCandidates: config.MaxCandidates, MismatchPrior: config.MismatchPrior, PriorStrength: config.PriorStrength,
		PartitionAccessSec: costs.PartitionAccess.Seconds(), RowReadSec: costs.RowRead.Seconds(),
		Concurrency: costs.Concurrency, NetworkRTTSec: costs.NetworkRTT.Seconds(),
		NetworkBytesPerSecond: costs.NetworkBytesPerSecond, NodeWireBytes: costs.NodeWireBytes,
		HashCostSec: costs.HashCost.Seconds(), CompareCostSec: costs.CompareCost.Seconds(),
		AdaptationRate: costs.AdaptationRate,
	}
}
