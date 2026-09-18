package cassandra

import (
	"bytes"
	"context"
	"fmt"

	locator "github.com/SirojWongpitakroj/hmf-audit/internal/all"
)

// ALLPageReader loads and decodes one persisted ALL page at a time.
type ALLPageReader struct {
	repo           *ALLRepo
	treeID         string
	pagesPerBucket int64
}

func NewALLPageReader(repo *ALLRepo, treeID string, pagesPerBucket int64) (*ALLPageReader, error) {
	if repo == nil {
		return nil, fmt.Errorf("new ALL page reader: repository is nil")
	}
	if treeID == "" {
		return nil, fmt.Errorf("new ALL page reader: tree ID is required")
	}
	if pagesPerBucket <= 0 {
		return nil, fmt.Errorf("new ALL page reader: pages per bucket must be positive")
	}
	return &ALLPageReader{repo: repo, treeID: treeID, pagesPerBucket: pagesPerBucket}, nil
}

func (reader *ALLPageReader) ReadPage(ctx context.Context, pageID int64) (*locator.Page, error) {
	stored, err := reader.repo.GetPage(ctx, reader.treeID, pageID, reader.pagesPerBucket)
	if err != nil {
		return nil, err
	}
	if stored.FormatVersion != locator.PageFormatVersion {
		return nil, fmt.Errorf("read ALL page %d: format version %d, want %d",
			pageID, stored.FormatVersion, locator.PageFormatVersion)
	}
	page, err := locator.UnmarshalStoredPage(
		stored.PageData,
		stored.PageID,
		stored.ParentPageID,
		stored.NextPageID,
		stored.PageHash,
	)
	if err != nil {
		return nil, err
	}
	return &page, nil
}

// ResolveLocatorQuery reads the current ALL state, ensures it matches the
// caller's trusted checkpoint root, and traverses persisted pages on demand.
func (repo *ALLRepo) ResolveLocatorQuery(ctx context.Context, treeID string,
	trustedRoot [32]byte, query locator.LocatorQuery) (locator.LocatorRangeResult, error) {

	state, err := repo.GetTreeState(ctx, treeID)
	if err != nil {
		return locator.LocatorRangeResult{}, err
	}
	if len(state.RootHash) != len(trustedRoot) || !bytes.Equal(state.RootHash, trustedRoot[:]) {
		return locator.LocatorRangeResult{}, fmt.Errorf("resolve locator query: stored ALL state does not match trusted locator root")
	}
	reader, err := NewALLPageReader(repo, treeID, int64(state.PagesPerBucket))
	if err != nil {
		return locator.LocatorRangeResult{}, err
	}
	return locator.ResolveWithReader(ctx, reader, state.RootPageID, trustedRoot, query)
}
