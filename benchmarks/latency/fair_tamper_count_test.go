package main

import (
	"fmt"
	"testing"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

func TestFairTamperedAddressesUseStratumCenters(t *testing.T) {
	addresses := make([]hpp.PhysicalAddress, 16)
	for index := range addresses {
		addresses[index] = hpp.PhysicalAddress{RegionID: fmt.Sprintf("R%d", index)}
	}

	tampered, err := fairTamperedAddresses(addresses, 4)
	if err != nil {
		t.Fatal(err)
	}
	want := []hpp.PhysicalAddress{addresses[2], addresses[6], addresses[10], addresses[14]}
	for index := range want {
		if tampered[index] != want[index] {
			t.Fatalf("tampered[%d] = %+v, want %+v", index, tampered[index], want[index])
		}
	}
}

func TestFairTamperedAddressesRejectInvalidCount(t *testing.T) {
	if _, err := fairTamperedAddresses(make([]hpp.PhysicalAddress, 8), 9); err == nil {
		t.Fatal("expected tamper count larger than batch to fail")
	}
}

func TestFairClusteredTwoSupportsMaximumRequestCount(t *testing.T) {
	layout, err := newFairLayout([]int{20_000}, 1, 8192)
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := layout.addresses("clustered-2", 16384)
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 16384 || addresses[0] != layout.address(0) ||
		addresses[len(addresses)-1] != layout.address(16383) {
		t.Fatalf("unexpected q=16384 endpoints: first=%+v last=%+v",
			addresses[0], addresses[len(addresses)-1])
	}
}
