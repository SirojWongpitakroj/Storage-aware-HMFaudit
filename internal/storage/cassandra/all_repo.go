package cassandra

import (
	"context"
	"fmt"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
)

type ALLPage struct {
	TreeID        string
	BucketID      int64
	PageID        int64
	IsLeaf        bool
	ParentPageID  *int64 //handle root which parent = nil
	NextPageID    *int64 //handle nextPageID null
	PageData      []byte
	FormatVersion int32
	PageHash      []byte
}

type ALLTreeState struct {
	TreeID         string
	RootPageID     int64
	RootHash       []byte
	NextPageID     int64
	TreeHeight     int32
	TreeOrder      int32
	RecordCount    int64
	PageCount      int64
	PagesPerBucket int32
	UpdatedAt      time.Time
}

type ALLRepo struct {
	session *gocql.Session
}

func NewALLRepo(session *gocql.Session) *ALLRepo {
	return &ALLRepo{
		session: session,
	}
}

// helper func

func PageBucketID(pageID, pagesPerBucket int64) (int64, error) {
	if pageID < 0 || pagesPerBucket <= 0 {
		return 0, fmt.Errorf("pageBucketID receives only positive pageID and pagesPerBucket")
	}
	return pageID / pagesPerBucket, nil
}

func (r *ALLRepo) UpsertPage(ctx context.Context, page ALLPage) error {
	query := `
			INSERT INTO all_pages (
			tree_id,
			bucket_id,
			page_id,
			is_leaf,
			parent_page_id,
			next_page_id,
			page_data,
			format_version,
			page_hash
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
		`

	err := r.session.Query(
		query,
		page.TreeID,
		page.BucketID,
		page.PageID,
		page.IsLeaf,
		page.ParentPageID,
		page.NextPageID,
		page.PageData,
		page.FormatVersion,
		page.PageHash,
	).ExecContext(ctx)

	if err != nil {
		return fmt.Errorf(`upsert page %d: %w`, page.PageID, err)
	}
	return nil
}

func (r *ALLRepo) UpsertPages(ctx context.Context, pages []ALLPage) error {
	if len(pages) == 0 {
		return nil
	}

	type partitionKey struct {
		treeID   string
		bucketID int64
	}

	partitions := make(map[partitionKey][]ALLPage)
	for _, page := range pages {
		key := partitionKey{
			treeID:   page.TreeID,
			bucketID: page.BucketID,
		}
		partitions[key] = append(partitions[key], page)
	}

	query := `
			INSERT INTO all_pages (
			tree_id,
			bucket_id,
			page_id,
			is_leaf,
			parent_page_id,
			next_page_id,
			page_data,
			format_version,
			page_hash
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
		`

	results := make(chan error, len(partitions))

	for _, partitionPages := range partitions {
		go func(partitionPages []ALLPage) {
			batch := r.session.Batch(gocql.UnloggedBatch)

			for _, page := range partitionPages {
				batch = batch.Query(
					query,
					page.TreeID,
					page.BucketID,
					page.PageID,
					page.IsLeaf,
					page.ParentPageID,
					page.NextPageID,
					page.PageData,
					page.FormatVersion,
					page.PageHash,
				)
			}

			results <- batch.ExecContext(ctx)
		}(partitionPages)
	}

	var firstErr error
	for range partitions {
		if err := <-results; err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if firstErr != nil {
		return fmt.Errorf("upsert batch pages: %w", firstErr)
	}

	return nil
}

// SaveLocatorUpdate persists changed pages before publishing their resulting
// root state. Callers must provide pages and state from the same ALL update.
func (r *ALLRepo) SaveLocatorUpdate(ctx context.Context, pages []ALLPage, state ALLTreeState) error {
	if err := r.UpsertPages(ctx, pages); err != nil {
		return fmt.Errorf("save locator update pages: %w", err)
	}
	if err := r.UpsertTreeState(ctx, state); err != nil {
		return fmt.Errorf("save locator update state: %w", err)
	}
	return nil
}

func (r *ALLRepo) GetPage(ctx context.Context, treeID string,
	pageID int64, pagesPerBucket int64) (ALLPage, error) {

	page := ALLPage{}
	bucketID, err := PageBucketID(pageID, pagesPerBucket)
	if err != nil {
		return ALLPage{}, err
	}

	query := `
		SELECT 
			tree_id,
			bucket_id,
			page_id,
			is_leaf,
			parent_page_id,
			next_page_id,
			page_data,
			format_version,
			page_hash 
		FROM all_pages
		WHERE tree_id = ?
		AND bucket_id = ?
		AND page_id = ?;
	`

	err = r.session.Query(
		query,
		treeID,
		bucketID,
		pageID,
	).ScanContext(
		ctx,
		&page.TreeID,
		&page.BucketID,
		&page.PageID,
		&page.IsLeaf,
		&page.ParentPageID,
		&page.NextPageID,
		&page.PageData,
		&page.FormatVersion,
		&page.PageHash,
	)

	if err != nil {
		return ALLPage{}, fmt.Errorf("get ALL Page %d: %w", pageID, err)
	}

	return page, nil
}

func (r *ALLRepo) GetPages(ctx context.Context, treeID string,
	pageIDs []int64, pagesPerBucket int64) ([]ALLPage, error) {

	if len(pageIDs) == 0 {
		return []ALLPage{}, nil
	}

	bucketIDs := make(map[int64][]int64)
	//groupby bucketIDs (same partition)
	for _, pageID := range pageIDs {
		bucketID, err := PageBucketID(pageID, pagesPerBucket)
		if err != nil {
			return nil, err
		}
		bucketIDs[bucketID] = append(bucketIDs[bucketID], pageID)
	}

	query := `
		SELECT
			tree_id,
			bucket_id,
			page_id,
			is_leaf,
			parent_page_id,
			next_page_id,
			page_data,
			format_version,
			page_hash
		FROM all_pages
		WHERE tree_id = ?
		AND bucket_id = ?
		AND page_id IN ?;
	`

	type result struct {
		pages []ALLPage
		err   error
	}

	//channel for concurrent fetch count tracking
	//make Channel of size of unique number of partition touched
	results := make(chan result, len(bucketIDs))

	for bucketID, ids := range bucketIDs {
		//concurrent fetch
		go func(bucketID int64, ids []int64) {
			iter := r.session.Query(
				query,
				treeID,
				bucketID,
				ids,
			).IterContext(ctx)

			pages := make([]ALLPage, 0, len(ids))
			for {
				page := ALLPage{}
				if !iter.Scan(
					&page.TreeID,
					&page.BucketID,
					&page.PageID,
					&page.IsLeaf,
					&page.ParentPageID,
					&page.NextPageID,
					&page.PageData,
					&page.FormatVersion,
					&page.PageHash,
				) {
					break
				}
				pages = append(pages, page)
			}

			if err := iter.Close(); err != nil {
				results <- result{err: err}
				return
			}

			results <- result{pages: pages}
		}(bucketID, ids)
	}

	//read result stored in channel store in map[pageID]ALLPage object
	pagesByID := make(map[int64]ALLPage, len(pageIDs))
	for range bucketIDs {
		result := <-results
		if result.err != nil {
			return nil, fmt.Errorf("get ALL pages: %w", result.err)
		}
		for _, page := range result.pages {
			pagesByID[page.PageID] = page
		}
	}

	// return slice of ALLPage in the same order as PageID queried from arg
	pages := make([]ALLPage, 0, len(pageIDs))
	for _, pageID := range pageIDs {
		page, exists := pagesByID[pageID]
		if !exists {
			return nil, fmt.Errorf("get ALL page %d: %w", pageID, gocql.ErrNotFound)
		}
		pages = append(pages, page)
	}

	return pages, nil
}

func (r *ALLRepo) UpsertTreeState(ctx context.Context, state ALLTreeState) error {
	query := `
		INSERT INTO all_tree_state (
			tree_id,
			root_page_id,
			root_hash,
			next_page_id,
			tree_height,
			tree_order,
			record_count,
			page_count,
			pages_per_bucket,
			updated_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`

	err := r.session.Query(
		query,
		state.TreeID,
		state.RootPageID,
		state.RootHash,
		state.NextPageID,
		state.TreeHeight,
		state.TreeOrder,
		state.RecordCount,
		state.PageCount,
		state.PagesPerBucket,
		state.UpdatedAt,
	).ExecContext(ctx)

	if err != nil {
		return fmt.Errorf("upsert ALL tree state %s: %w", state.TreeID, err)
	}

	return nil
}

func (r *ALLRepo) GetTreeState(ctx context.Context,
	treeID string) (ALLTreeState, error) {

	state := ALLTreeState{}

	query := `
		SELECT
			tree_id,
			root_page_id,
			root_hash,
			next_page_id,
			tree_height,
			tree_order,
			record_count,
			page_count,
			pages_per_bucket,
			updated_at
		FROM all_tree_state
		WHERE tree_id = ?;
	`

	err := r.session.Query(
		query,
		treeID,
	).ScanContext(
		ctx,
		&state.TreeID,
		&state.RootPageID,
		&state.RootHash,
		&state.NextPageID,
		&state.TreeHeight,
		&state.TreeOrder,
		&state.RecordCount,
		&state.PageCount,
		&state.PagesPerBucket,
		&state.UpdatedAt,
	)

	if err != nil {
		return ALLTreeState{}, fmt.Errorf("get ALL tree state %s: %w", treeID, err)
	}

	return state, nil
}
