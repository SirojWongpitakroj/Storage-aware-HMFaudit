package checkpoint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// MockAnchor preserves Ethereum-like receipt semantics without measuring
// network or consensus latency. Recommitting the same value is idempotent.
type MockAnchor struct {
	mu          sync.Mutex
	nextBlock   int64
	receipts    map[[32]byte]AnchorReceipt
	commitCount int64
	clock       func() time.Time
}

func NewMockAnchor(startBlockHeight int64) *MockAnchor {
	if startBlockHeight < 0 {
		startBlockHeight = 0
	}
	return &MockAnchor{
		nextBlock: startBlockHeight,
		receipts:  make(map[[32]byte]AnchorReceipt),
		clock:     time.Now,
	}
}

func (anchor *MockAnchor) Commit(ctx context.Context,
	commitment [32]byte) (AnchorReceipt, error) {

	if err := ctx.Err(); err != nil {
		return AnchorReceipt{}, err
	}
	anchor.mu.Lock()
	defer anchor.mu.Unlock()
	if receipt, exists := anchor.receipts[commitment]; exists {
		return receipt, nil
	}
	txDigest := sha256.Sum256(append([]byte("MOCK_ETH_TX"), commitment[:]...))
	receipt := AnchorReceipt{
		TransactionHash: "0x" + hex.EncodeToString(txDigest[:]),
		BlockHeight:     anchor.nextBlock,
		AnchoredAt:      anchor.clock().UTC(),
	}
	anchor.nextBlock++
	anchor.commitCount++
	anchor.receipts[commitment] = receipt
	return receipt, nil
}

func (anchor *MockAnchor) Receipt(commitment [32]byte) (AnchorReceipt, bool) {
	anchor.mu.Lock()
	defer anchor.mu.Unlock()
	receipt, exists := anchor.receipts[commitment]
	return receipt, exists
}

func (anchor *MockAnchor) CommitCount() int64 {
	anchor.mu.Lock()
	defer anchor.mu.Unlock()
	return anchor.commitCount
}
