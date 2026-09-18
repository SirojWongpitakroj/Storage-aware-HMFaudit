package checkpoint

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

const stateDomain = "STATE"

// StateCommitment calculates C_J = H("STATE" || uint64be(J) || R_L || R_G).
func StateCommitment(sequence int64, locatorRoot, globalHMFRoot [32]byte) ([32]byte, error) {
	if sequence <= 0 {
		return [32]byte{}, fmt.Errorf("checkpoint commitment: sequence must be positive")
	}
	sequenceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(sequenceBytes, uint64(sequence))
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(stateDomain))
	_, _ = hasher.Write(sequenceBytes)
	_, _ = hasher.Write(locatorRoot[:])
	_, _ = hasher.Write(globalHMFRoot[:])
	var result [32]byte
	copy(result[:], hasher.Sum(nil))
	return result, nil
}

func VerifyStateCommitment(value Checkpoint) error {
	expected, err := StateCommitment(value.Sequence, value.LocatorRoot, value.GlobalHMFRoot)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(expected[:], value.StateCommitment[:]) != 1 {
		return fmt.Errorf("checkpoint commitment does not match its sequence and roots")
	}
	return nil
}
