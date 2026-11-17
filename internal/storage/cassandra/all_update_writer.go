package cassandra

import (
	"context"
	"fmt"
	"time"

	"github.com/SirojWongpitakroj/hmf-audit/internal/all"
	gocql "github.com/apache/cassandra-gocql-driver/v2"
)

// ALLUpdateWriter persists the updates emitted by one ALL worker.
type ALLUpdateWriter struct {
	repo           *ALLRepo
	treeID         string
	treeOrder      int
	pagesPerBucket int64
}

func NewALLUpdateWriter(session *gocql.Session, treeID string,
	treeOrder int, pagesPerBucket int64) (*ALLUpdateWriter, error) {

	if treeID == "" {
		return nil, fmt.Errorf("new ALL update writer: tree ID is required")
	}
	if treeOrder < 3 {
		return nil, fmt.Errorf("new ALL update writer: tree order must be at least 3")
	}
	if pagesPerBucket <= 0 {
		return nil, fmt.Errorf("new ALL update writer: pages per bucket must be positive")
	}

	return &ALLUpdateWriter{
		repo:           NewALLRepo(session),
		treeID:         treeID,
		treeOrder:      treeOrder,
		pagesPerBucket: pagesPerBucket,
	}, nil
}

// PersistUpdate writes changed pages before publishing the resulting tree state.
func (w *ALLUpdateWriter) PersistUpdate(ctx context.Context, update all.LocatorUpdate) error {
	pages, err := w.pages(update.Pages)
	if err != nil {
		return err
	}

	state := ALLTreeState{
		TreeID:         w.treeID,
		RootPageID:     update.RootPageID,
		RootHash:       copyHash(update.RootHash),
		NextPageID:     update.NextPageID,
		TreeHeight:     int32(update.Height),
		TreeOrder:      int32(w.treeOrder),
		RecordCount:    update.RecordCount,
		PageCount:      update.NextPageID,
		PagesPerBucket: int32(w.pagesPerBucket),
		UpdatedAt:      time.Now().UTC(),
	}

	return w.repo.SaveLocatorUpdate(ctx, pages, state)
}

// PersistSnapshot writes a complete tree with bounded page memory, publishing
// its root only after every page has been stored. This is useful when seeding a
// large fixture whose final pages would be too large to marshal in one update.
func (w *ALLUpdateWriter) PersistSnapshot(ctx context.Context, tree *all.LocatorTree) error {
	if tree == nil || tree.RootPage == nil {
		return fmt.Errorf("persist ALL snapshot: tree and root page are required")
	}
	const pageChunkSize = 256
	seen := make(map[int64]struct{})
	stack := []*all.Page{tree.RootPage}
	chunk := make([]all.Page, 0, pageChunkSize)
	flush := func() error {
		if len(chunk) == 0 {
			return nil
		}
		pages, err := w.pages(chunk)
		if err != nil {
			return err
		}
		if err := w.repo.UpsertPages(ctx, pages); err != nil {
			return err
		}
		chunk = chunk[:0]
		return nil
	}
	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		page := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if page == nil {
			continue
		}
		if _, exists := seen[page.PageID]; exists {
			continue
		}
		seen[page.PageID] = struct{}{}
		chunk = append(chunk, *page)
		if len(chunk) == pageChunkSize {
			if err := flush(); err != nil {
				return fmt.Errorf("persist ALL snapshot pages: %w", err)
			}
		}
		for _, child := range page.Children {
			stack = append(stack, child)
		}
	}
	if err := flush(); err != nil {
		return fmt.Errorf("persist ALL snapshot pages: %w", err)
	}
	state := ALLTreeState{
		TreeID: w.treeID, RootPageID: tree.RootPageID,
		RootHash: copyHash(tree.RootHash), NextPageID: tree.NextPageID,
		TreeHeight: int32(tree.Height), TreeOrder: int32(w.treeOrder),
		RecordCount: tree.LeafCount, PageCount: tree.NextPageID,
		PagesPerBucket: int32(w.pagesPerBucket), UpdatedAt: time.Now().UTC(),
	}
	if err := w.repo.UpsertTreeState(ctx, state); err != nil {
		return fmt.Errorf("persist ALL snapshot state: %w", err)
	}
	return nil
}

// PersistUpdates consumes ALL.Updates in order until cancellation or failure.
func (w *ALLUpdateWriter) PersistUpdates(ctx context.Context, updates <-chan all.LocatorUpdate) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case update, ok := <-updates:
			if !ok {
				return nil
			}
			if err := w.PersistUpdate(ctx, update); err != nil {
				return err
			}
		}
	}
}

func (w *ALLUpdateWriter) pages(updated []all.Page) ([]ALLPage, error) {
	pages := make([]ALLPage, 0, len(updated))
	for _, page := range updated {
		bucketID, err := PageBucketID(page.PageID, w.pagesPerBucket)
		if err != nil {
			return nil, err
		}
		pageData, err := all.MarshalPage(page)
		if err != nil {
			return nil, err
		}

		pages = append(pages, ALLPage{
			TreeID:        w.treeID,
			BucketID:      bucketID,
			PageID:        page.PageID,
			IsLeaf:        page.IsLeaf,
			ParentPageID:  page.ParentPageID,
			NextPageID:    nextPageID(page.Next),
			PageData:      pageData,
			FormatVersion: all.PageFormatVersion,
			PageHash:      copyHash(page.Hash),
		})
	}
	return pages, nil
}

func nextPageID(page *all.Page) *int64 {
	if page == nil {
		return nil
	}
	pageID := page.PageID
	return &pageID
}

func copyHash(hash [32]byte) []byte {
	return append([]byte(nil), hash[:]...)
}
