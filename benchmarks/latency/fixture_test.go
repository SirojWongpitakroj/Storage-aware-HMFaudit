package main

import (
	"context"
	"testing"

	"github.com/SirojWongpitakroj/hmf-audit/internal/localization"
)

func TestSyntheticBenchmarkScenarioIsValid(t *testing.T) {
	forest, err := newSyntheticForest()
	if err != nil {
		t.Fatalf("build synthetic forest: %v", err)
	}
	scenario, err := prepareScenario(context.Background(), forest, "scattered", 16)
	if err != nil {
		t.Fatalf("prepare scenario: %v", err)
	}
	if len(scenario.localization.Proof.Suspects) != 1 ||
		scenario.localization.Proof.Suspects[0].Classification != localization.LeafMismatch {
		t.Fatalf("localization suspects = %+v, want one leaf mismatch",
			scenario.localization.Proof.Suspects)
	}
	if err := localization.VerifyProof(scenario.localization.Proof,
		scenario.addresses, scenario.reference.CalculatedGlobalRoot); err != nil {
		t.Fatalf("verify localization proof: %v", err)
	}
}
