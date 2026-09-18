package all

import (
	"context"
	"crypto/subtle"
	"fmt"
	"sort"
	"uuid"
)

// PageReader loads one decoded ALL page by its stable PageID.
type PageReader interface {
	ReadPage(ctx context.Context, pageID int64) (*Page, error)
}

type pathStep struct {
	page       *Page
	childIndex int
}

// Bounds converts an exact-prefix logical query into a half-open ALL key
// range. A zero LogID includes every log at StartTime and excludes every log
// at EndTime.
func (query LocatorQuery) Bounds() (LocatorKey, LocatorKey, error) {
	if query.TenantID == "" || query.ServiceID == "" || query.LogType == "" || query.RegionID == "" {
		return LocatorKey{}, LocatorKey{}, fmt.Errorf("locator query: tenant, service, log type, and region are required")
	}
	if query.StartTime.IsZero() || query.EndTime.IsZero() {
		return LocatorKey{}, LocatorKey{}, fmt.Errorf("locator query: start and end times are required")
	}
	if !query.StartTime.Before(query.EndTime) {
		return LocatorKey{}, LocatorKey{}, fmt.Errorf("locator query: start time must be before end time")
	}

	key := LocatorKey{
		TenantID:  query.TenantID,
		ServiceID: query.ServiceID,
		LogType:   query.LogType,
		RegionID:  query.RegionID,
		LogID:     uuid.UUID{},
	}
	lower := key
	lower.EventTime = query.StartTime
	upper := key
	upper.EventTime = query.EndTime
	return lower, upper, nil
}

// Resolve converts a logical query into key bounds and resolves it against
// the in-memory tree.
func (tree *LocatorTree) Resolve(query LocatorQuery) (LocatorRangeResult, error) {
	lower, upper, err := query.Bounds()
	if err != nil {
		return LocatorRangeResult{}, err
	}
	return tree.ResolveRange(lower, upper)
}

// ResolveRange resolves [lower, upper) against the in-memory tree. It uses the
// same PageReader traversal as storage-backed resolution.
func (tree *LocatorTree) ResolveRange(lower, upper LocatorKey) (LocatorRangeResult, error) {
	if tree == nil || tree.RootPage == nil {
		return LocatorRangeResult{}, fmt.Errorf("resolve locator range: tree is empty")
	}
	reader := newMemoryPageReader(tree.RootPage)
	return ResolveRangeWithReader(
		context.Background(),
		reader,
		tree.RootPageID,
		tree.RootHash,
		lower,
		upper,
	)
}

// ResolveWithReader converts a query into bounds and resolves it by loading
// pages on demand. trustedRoot must come from the trusted checkpoint.
func ResolveWithReader(ctx context.Context, reader PageReader, rootPageID int64,
	trustedRoot [32]byte, query LocatorQuery) (LocatorRangeResult, error) {

	lower, upper, err := query.Bounds()
	if err != nil {
		return LocatorRangeResult{}, err
	}
	return ResolveRangeWithReader(ctx, reader, rootPageID, trustedRoot, lower, upper)
}

// ResolveRangeWithReader fetches one page at a time while traversing the ALL.
// The leaf chain is only a scan optimization; both range boundaries are found
// independently through authenticated internal-tree paths.
func ResolveRangeWithReader(ctx context.Context, reader PageReader, rootPageID int64,
	trustedRoot [32]byte, lower, upper LocatorKey) (LocatorRangeResult, error) {

	if reader == nil {
		return LocatorRangeResult{}, fmt.Errorf("resolve locator range: page reader is nil")
	}
	reader = newCachingPageReader(reader)
	if lower.Compare(upper) >= 0 {
		return LocatorRangeResult{}, fmt.Errorf("resolve locator range: lower bound must sort before upper bound")
	}

	root, err := reader.ReadPage(ctx, rootPageID)
	if err != nil {
		return LocatorRangeResult{}, fmt.Errorf("resolve locator range: read root page %d: %w", rootPageID, err)
	}
	if root == nil {
		return LocatorRangeResult{}, fmt.Errorf("resolve locator range: root page %d is nil", rootPageID)
	}
	if subtle.ConstantTimeCompare(root.Hash[:], trustedRoot[:]) != 1 {
		return LocatorRangeResult{}, fmt.Errorf("resolve locator range: root page hash does not match trusted locator root")
	}

	startLeaf, startPath, err := findLeaf(ctx, reader, root, lower)
	if err != nil {
		return LocatorRangeResult{}, err
	}
	startIndex := lowerBound(startLeaf.Keys, lower)
	predecessor, err := predecessorEntry(ctx, reader, startLeaf, startIndex, startPath)
	if err != nil {
		return LocatorRangeResult{}, err
	}
	successor, err := lowerBoundEntry(ctx, reader, root, upper)
	if err != nil {
		return LocatorRangeResult{}, err
	}

	result := LocatorRangeResult{
		Entries:     make([]LocatorEntry, 0),
		Predecessor: predecessor,
		Successor:   successor,
	}

	leaf := startLeaf
	visitedLeaves := make(map[int64]struct{})
	scanComplete := false
	for leaf != nil {
		if _, visited := visitedLeaves[leaf.PageID]; visited {
			return LocatorRangeResult{}, fmt.Errorf("resolve locator range: leaf chain contains cycle at page %d", leaf.PageID)
		}
		visitedLeaves[leaf.PageID] = struct{}{}

		index := 0
		if leaf.PageID == startLeaf.PageID {
			index = startIndex
		}
		for ; index < len(leaf.Keys); index++ {
			key := leaf.Keys[index]
			if key.Compare(upper) >= 0 {
				scanComplete = true
				break
			}
			result.Entries = append(result.Entries, *entryAt(leaf, index))
		}
		if scanComplete {
			break
		}

		if leaf.Next == nil {
			break
		}
		nextPageID := leaf.Next.PageID
		leaf, err = reader.ReadPage(ctx, nextPageID)
		if err != nil {
			return LocatorRangeResult{}, fmt.Errorf("resolve locator range: read next leaf page %d: %w", nextPageID, err)
		}
		if leaf == nil || !leaf.IsLeaf {
			return LocatorRangeResult{}, fmt.Errorf("resolve locator range: next page %d is not a leaf", nextPageID)
		}
	}

	result.Proof, err = buildRangeProof(ctx, reader, root, startLeaf, startPath, result, trustedRoot)
	if err != nil {
		return LocatorRangeResult{}, err
	}
	if err := VerifyLocatorRangeResult(lower, upper, result, trustedRoot); err != nil {
		return LocatorRangeResult{}, fmt.Errorf("resolve locator range: verify generated proof: %w", err)
	}
	return result, nil
}

func findLeaf(ctx context.Context, reader PageReader, root *Page,
	key LocatorKey) (*Page, []pathStep, error) {

	page := root
	path := make([]pathStep, 0)
	for !page.IsLeaf {
		childIndex := page.findKeyIdx(key)
		if childIndex < 0 || childIndex >= len(page.Children) {
			return nil, nil, fmt.Errorf("find locator leaf: child index %d out of range for page %d", childIndex, page.PageID)
		}
		path = append(path, pathStep{page: page, childIndex: childIndex})
		child, err := readChild(ctx, reader, page, childIndex)
		if err != nil {
			return nil, nil, err
		}
		page = child
	}
	return page, path, nil
}

func lowerBoundEntry(ctx context.Context, reader PageReader, root *Page,
	key LocatorKey) (*LocatorEntry, error) {

	leaf, path, err := findLeaf(ctx, reader, root, key)
	if err != nil {
		return nil, err
	}
	return successorEntry(ctx, reader, leaf, lowerBound(leaf.Keys, key), path)
}

func predecessorEntry(ctx context.Context, reader PageReader, leaf *Page,
	index int, path []pathStep) (*LocatorEntry, error) {

	if index > 0 {
		return entryAt(leaf, index-1), nil
	}

	// There is no Prev link. Walk up to the nearest ancestor for which the
	// selected child has a left sibling, then fetch down that sibling's right edge.
	for level := len(path) - 1; level >= 0; level-- {
		step := path[level]
		if step.childIndex == 0 {
			continue
		}

		page, err := readChild(ctx, reader, step.page, step.childIndex-1)
		if err != nil {
			return nil, err
		}
		for !page.IsLeaf {
			if len(page.Children) == 0 {
				return nil, fmt.Errorf("find predecessor: internal page %d has no children", page.PageID)
			}
			page, err = readChild(ctx, reader, page, len(page.Children)-1)
			if err != nil {
				return nil, err
			}
		}
		if len(page.Keys) == 0 {
			return nil, nil
		}
		return entryAt(page, len(page.Keys)-1), nil
	}
	return nil, nil
}

func successorEntry(ctx context.Context, reader PageReader, leaf *Page,
	index int, path []pathStep) (*LocatorEntry, error) {

	if index < len(leaf.Keys) {
		return entryAt(leaf, index), nil
	}

	// Walk up to the nearest ancestor for which the selected child has a
	// right sibling, then fetch down that sibling's left edge.
	for level := len(path) - 1; level >= 0; level-- {
		step := path[level]
		if step.childIndex+1 >= len(step.page.Children) {
			continue
		}

		page, err := readChild(ctx, reader, step.page, step.childIndex+1)
		if err != nil {
			return nil, err
		}
		for !page.IsLeaf {
			if len(page.Children) == 0 {
				return nil, fmt.Errorf("find successor: internal page %d has no children", page.PageID)
			}
			page, err = readChild(ctx, reader, page, 0)
			if err != nil {
				return nil, err
			}
		}
		if len(page.Keys) == 0 {
			return nil, nil
		}
		return entryAt(page, 0), nil
	}
	return nil, nil
}

func readChild(ctx context.Context, reader PageReader, parent *Page,
	childIndex int) (*Page, error) {

	if childIndex < 0 || childIndex >= len(parent.Children) {
		return nil, fmt.Errorf("read child: child index %d out of range for page %d", childIndex, parent.PageID)
	}
	expected := parent.Children[childIndex]
	if expected == nil {
		return nil, fmt.Errorf("read child: page %d has nil child %d", parent.PageID, childIndex)
	}
	child, err := reader.ReadPage(ctx, expected.PageID)
	if err != nil {
		return nil, fmt.Errorf("read child page %d: %w", expected.PageID, err)
	}
	if child == nil {
		return nil, fmt.Errorf("read child page %d: page is nil", expected.PageID)
	}
	if subtle.ConstantTimeCompare(child.Hash[:], expected.Hash[:]) != 1 {
		return nil, fmt.Errorf("read child page %d: hash does not match parent reference", expected.PageID)
	}
	return child, nil
}

func lowerBound(keys []LocatorKey, target LocatorKey) int {
	return sort.Search(len(keys), func(index int) bool {
		return keys[index].Compare(target) >= 0
	})
}

func entryAt(page *Page, index int) *LocatorEntry {
	entry := &LocatorEntry{PageID: page.PageID, Key: page.Keys[index]}
	if page.Values[index] != nil {
		value := *page.Values[index]
		entry.Value = &value
	}
	return entry
}

func buildRangeProof(ctx context.Context, reader PageReader, root, startLeaf *Page,
	startPath []pathStep, result LocatorRangeResult, trustedRoot [32]byte) (LocatorRangeProof, error) {

	proof := LocatorRangeProof{Leaves: make([]LocatorLeafProof, 0)}
	included := make(map[int64]struct{})
	add := func(leaf *Page, path []pathStep) error {
		if _, exists := included[leaf.PageID]; exists {
			return nil
		}
		leafProof, err := makeLeafProof(leaf, path)
		if err != nil {
			return err
		}
		reconstructed, err := ReconstructLocatorRoot(leafProof)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(reconstructed[:], trustedRoot[:]) != 1 {
			return fmt.Errorf("build locator proof: leaf page %d reconstructs an untrusted root", leaf.PageID)
		}
		if len(proof.Leaves) == 0 {
			proof.ReconstructedRoot = reconstructed
		}
		proof.Leaves = append(proof.Leaves, leafProof)
		included[leaf.PageID] = struct{}{}
		return nil
	}

	if err := add(startLeaf, startPath); err != nil {
		return LocatorRangeProof{}, err
	}
	entries := make([]LocatorEntry, 0, len(result.Entries)+2)
	if result.Predecessor != nil {
		entries = append(entries, *result.Predecessor)
	}
	entries = append(entries, result.Entries...)
	if result.Successor != nil {
		entries = append(entries, *result.Successor)
	}
	for _, entry := range entries {
		if _, exists := included[entry.PageID]; exists {
			continue
		}
		leaf, path, err := findLeaf(ctx, reader, root, entry.Key)
		if err != nil {
			return LocatorRangeProof{}, err
		}
		if leaf.PageID != entry.PageID {
			return LocatorRangeProof{}, fmt.Errorf(
				"build locator proof: key resolved to page %d, expected page %d",
				leaf.PageID, entry.PageID,
			)
		}
		if err := add(leaf, path); err != nil {
			return LocatorRangeProof{}, err
		}
	}
	ordered, err := orderLeafProofs(proof.Leaves)
	if err != nil {
		return LocatorRangeProof{}, err
	}
	proof.Leaves = ordered
	return proof, nil
}

func orderLeafProofs(leaves []LocatorLeafProof) ([]LocatorLeafProof, error) {
	byID := make(map[int64]LocatorLeafProof, len(leaves))
	incoming := make(map[int64]bool, len(leaves))
	for _, leaf := range leaves {
		if _, exists := byID[leaf.PageID]; exists {
			return nil, fmt.Errorf("order locator proofs: duplicate leaf page ID %d", leaf.PageID)
		}
		byID[leaf.PageID] = leaf
	}
	for _, leaf := range leaves {
		if leaf.NextPageID != nil {
			if _, included := byID[*leaf.NextPageID]; included {
				incoming[*leaf.NextPageID] = true
			}
		}
	}

	var head *LocatorLeafProof
	for _, leaf := range leaves {
		if incoming[leaf.PageID] {
			continue
		}
		if head != nil {
			return nil, fmt.Errorf("order locator proofs: represented leaves are not one chain")
		}
		copy := leaf
		head = &copy
	}
	if head == nil {
		return nil, fmt.Errorf("order locator proofs: represented leaf chain has no head")
	}

	ordered := make([]LocatorLeafProof, 0, len(leaves))
	visited := make(map[int64]bool, len(leaves))
	curr := *head
	for {
		if visited[curr.PageID] {
			return nil, fmt.Errorf("order locator proofs: cycle at leaf page %d", curr.PageID)
		}
		visited[curr.PageID] = true
		ordered = append(ordered, curr)
		if curr.NextPageID == nil {
			break
		}
		next, included := byID[*curr.NextPageID]
		if !included {
			break
		}
		curr = next
	}
	if len(ordered) != len(leaves) {
		return nil, fmt.Errorf("order locator proofs: represented leaves are not consecutive")
	}
	return ordered, nil
}

func makeLeafProof(leaf *Page, path []pathStep) (LocatorLeafProof, error) {
	if leaf == nil || !leaf.IsLeaf {
		return LocatorLeafProof{}, fmt.Errorf("make locator proof: page is not a leaf")
	}
	proof := LocatorLeafProof{
		PageID:     leaf.PageID,
		NextPageID: pageIDPointer(leaf.Next),
		Keys:       append([]LocatorKey(nil), leaf.Keys...),
		Values:     copyLocatorValues(leaf.Values),
		Path:       make([]LocatorProofStep, 0, len(path)),
	}
	for index := len(path) - 1; index >= 0; index-- {
		pathPage := path[index].page
		childHashes := make([][32]byte, len(pathPage.Children))
		for childIndex, child := range pathPage.Children {
			if child == nil {
				return LocatorLeafProof{}, fmt.Errorf("make locator proof: page %d has nil child %d", pathPage.PageID, childIndex)
			}
			childHashes[childIndex] = child.Hash
		}
		proof.Path = append(proof.Path, LocatorProofStep{
			PageID:      pathPage.PageID,
			Keys:        append([]LocatorKey(nil), pathPage.Keys...),
			ChildIndex:  path[index].childIndex,
			ChildHashes: childHashes,
		})
	}
	return proof, nil
}

func copyLocatorValues(values []*LocatorValue) []*LocatorValue {
	result := make([]*LocatorValue, len(values))
	for index, value := range values {
		if value != nil {
			copy := *value
			result[index] = &copy
		}
	}
	return result
}

// ReconstructLocatorRoot hashes one complete leaf and then each proof step
// upward, returning the auditor-computed locator root R_L'.
func ReconstructLocatorRoot(proof LocatorLeafProof) ([32]byte, error) {
	if len(proof.Keys) != len(proof.Values) {
		return [32]byte{}, fmt.Errorf("reconstruct locator root: leaf keys and values do not match")
	}
	leaf := Page{
		PageID: proof.PageID,
		IsLeaf: true,
		Keys:   proof.Keys,
		Values: proof.Values,
	}
	if proof.NextPageID != nil {
		leaf.Next = &Page{PageID: *proof.NextPageID}
	}
	current := leaf.leafHash()

	for _, step := range proof.Path {
		if len(step.ChildHashes) != len(step.Keys)+1 {
			return [32]byte{}, fmt.Errorf("reconstruct locator root: page %d has inconsistent keys and child hashes", step.PageID)
		}
		if step.ChildIndex < 0 || step.ChildIndex >= len(step.ChildHashes) {
			return [32]byte{}, fmt.Errorf("reconstruct locator root: child index %d out of range for page %d", step.ChildIndex, step.PageID)
		}

		children := make([]*Page, len(step.ChildHashes))
		for index, hash := range step.ChildHashes {
			children[index] = &Page{Hash: hash}
		}
		children[step.ChildIndex].Hash = current
		parent := Page{Keys: step.Keys, Children: children}
		current = parent.internalHash()
	}
	return current, nil
}

// VerifyLocatorPathProofs independently reconstructs every represented leaf
// path and requires each calculated R_L' to equal trustedRoot.
func VerifyLocatorPathProofs(proof LocatorRangeProof, trustedRoot [32]byte) error {
	if len(proof.Leaves) == 0 {
		return fmt.Errorf("verify locator path proofs: proof has no leaves")
	}
	for _, leaf := range proof.Leaves {
		reconstructed, err := ReconstructLocatorRoot(leaf)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(reconstructed[:], trustedRoot[:]) != 1 {
			return fmt.Errorf("verify locator path proofs: leaf page %d does not reconstruct the trusted root", leaf.PageID)
		}
	}
	if subtle.ConstantTimeCompare(proof.ReconstructedRoot[:], trustedRoot[:]) != 1 {
		return fmt.Errorf("verify locator path proofs: reported reconstructed root does not match trusted root")
	}
	return nil
}

// VerifyLocatorQueryResult verifies path membership, authenticated leaf-chain
// continuity, exact range contents, and both boundaries for one logical query.
func VerifyLocatorQueryResult(query LocatorQuery, result LocatorRangeResult,
	trustedRoot [32]byte) error {

	lower, upper, err := query.Bounds()
	if err != nil {
		return err
	}
	return VerifyLocatorRangeResult(lower, upper, result, trustedRoot)
}

// VerifyLocatorRangeResult verifies that result contains every entry in
// [lower, upper), no entry outside it, and the immediate adjacent boundaries.
func VerifyLocatorRangeResult(lower, upper LocatorKey, result LocatorRangeResult,
	trustedRoot [32]byte) error {

	if lower.Compare(upper) >= 0 {
		return fmt.Errorf("verify locator range: lower bound must sort before upper bound")
	}
	if err := VerifyLocatorPathProofs(result.Proof, trustedRoot); err != nil {
		return err
	}
	if err := verifyConsecutiveLeafProofs(result.Proof.Leaves); err != nil {
		return err
	}

	proofEntries := flattenProofEntries(result.Proof.Leaves)
	expectedMatches := make([]LocatorEntry, 0)
	var expectedPredecessor *LocatorEntry
	var expectedSuccessor *LocatorEntry
	for index := range proofEntries {
		entry := proofEntries[index]
		switch {
		case entry.Key.Compare(lower) < 0:
			copy := entry
			expectedPredecessor = &copy
		case entry.Key.Compare(upper) < 0:
			expectedMatches = append(expectedMatches, entry)
		case expectedSuccessor == nil:
			copy := entry
			expectedSuccessor = &copy
		}
	}

	firstLeaf := result.Proof.Leaves[0]
	lastLeaf := result.Proof.Leaves[len(result.Proof.Leaves)-1]
	if expectedPredecessor == nil && !isLeftmostProof(firstLeaf) {
		return fmt.Errorf("verify locator range: missing predecessor or authenticated left tree edge")
	}
	if expectedSuccessor == nil {
		if lastLeaf.NextPageID != nil || !isRightmostProof(lastLeaf) {
			return fmt.Errorf("verify locator range: missing successor or authenticated right tree edge")
		}
	}

	if !optionalEntryEqual(result.Predecessor, expectedPredecessor) {
		return fmt.Errorf("verify locator range: predecessor is not the immediate entry before the lower bound")
	}
	if !optionalEntryEqual(result.Successor, expectedSuccessor) {
		return fmt.Errorf("verify locator range: successor is not the immediate entry at or after the upper bound")
	}
	if len(result.Entries) != len(expectedMatches) {
		return fmt.Errorf("verify locator range: got %d returned entries, proof contains %d matching entries",
			len(result.Entries), len(expectedMatches))
	}
	for index := range expectedMatches {
		if !locatorEntryEqual(result.Entries[index], expectedMatches[index]) {
			return fmt.Errorf("verify locator range: returned entry %d does not match authenticated leaf contents", index)
		}
	}
	return nil
}

func verifyConsecutiveLeafProofs(leaves []LocatorLeafProof) error {
	if len(leaves) == 0 {
		return fmt.Errorf("verify locator range: proof has no leaves")
	}
	height := len(leaves[0].Path)
	var previous *LocatorKey
	seenIDs := make(map[int64]bool, len(leaves))
	for leafIndex, leaf := range leaves {
		if seenIDs[leaf.PageID] {
			return fmt.Errorf("verify locator range: duplicate leaf page ID %d", leaf.PageID)
		}
		seenIDs[leaf.PageID] = true
		if len(leaf.Path) != height {
			return fmt.Errorf("verify locator range: leaf page %d has inconsistent tree depth", leaf.PageID)
		}
		if len(leaf.Keys) != len(leaf.Values) {
			return fmt.Errorf("verify locator range: leaf page %d has inconsistent keys and values", leaf.PageID)
		}
		if len(leaves) > 1 && len(leaf.Keys) == 0 {
			return fmt.Errorf("verify locator range: non-root leaf page %d is empty", leaf.PageID)
		}
		if leafIndex+1 < len(leaves) {
			if leaf.NextPageID == nil || *leaf.NextPageID != leaves[leafIndex+1].PageID {
				return fmt.Errorf("verify locator range: leaf pages %d and %d are not consecutive",
					leaf.PageID, leaves[leafIndex+1].PageID)
			}
		}
		for keyIndex := range leaf.Keys {
			key := leaf.Keys[keyIndex]
			if previous != nil && previous.Compare(key) >= 0 {
				return fmt.Errorf("verify locator range: proof leaf keys are not strictly ordered")
			}
			copy := key
			previous = &copy
		}
	}
	return nil
}

func flattenProofEntries(leaves []LocatorLeafProof) []LocatorEntry {
	count := 0
	for _, leaf := range leaves {
		count += len(leaf.Keys)
	}
	entries := make([]LocatorEntry, 0, count)
	for _, leaf := range leaves {
		for index, key := range leaf.Keys {
			entry := LocatorEntry{PageID: leaf.PageID, Key: key}
			if leaf.Values[index] != nil {
				copy := *leaf.Values[index]
				entry.Value = &copy
			}
			entries = append(entries, entry)
		}
	}
	return entries
}

func isLeftmostProof(leaf LocatorLeafProof) bool {
	for _, step := range leaf.Path {
		if step.ChildIndex != 0 {
			return false
		}
	}
	return true
}

func isRightmostProof(leaf LocatorLeafProof) bool {
	for _, step := range leaf.Path {
		if len(step.ChildHashes) == 0 || step.ChildIndex != len(step.ChildHashes)-1 {
			return false
		}
	}
	return true
}

func optionalEntryEqual(left, right *LocatorEntry) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return locatorEntryEqual(*left, *right)
}

func locatorEntryEqual(left, right LocatorEntry) bool {
	if left.PageID != right.PageID || left.Key.Compare(right.Key) != 0 {
		return false
	}
	if left.Value == nil || right.Value == nil {
		return left.Value == nil && right.Value == nil
	}
	return *left.Value == *right.Value
}

type cachingPageReader struct {
	source PageReader
	pages  map[int64]*Page
}

func newCachingPageReader(source PageReader) *cachingPageReader {
	return &cachingPageReader{source: source, pages: make(map[int64]*Page)}
}

func (reader *cachingPageReader) ReadPage(ctx context.Context, pageID int64) (*Page, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if page, exists := reader.pages[pageID]; exists {
		return page, nil
	}
	page, err := reader.source.ReadPage(ctx, pageID)
	if err != nil {
		return nil, err
	}
	reader.pages[pageID] = page
	return page, nil
}

type memoryPageReader struct {
	pages map[int64]*Page
}

func newMemoryPageReader(root *Page) *memoryPageReader {
	reader := &memoryPageReader{pages: make(map[int64]*Page)}
	var add func(*Page)
	add = func(page *Page) {
		if page == nil {
			return
		}
		if _, exists := reader.pages[page.PageID]; exists {
			return
		}
		reader.pages[page.PageID] = page
		for _, child := range page.Children {
			add(child)
		}
	}
	add(root)
	return reader
}

func (reader *memoryPageReader) ReadPage(_ context.Context, pageID int64) (*Page, error) {
	page, exists := reader.pages[pageID]
	if !exists {
		return nil, fmt.Errorf("read in-memory page %d: page not found", pageID)
	}
	return page, nil
}
