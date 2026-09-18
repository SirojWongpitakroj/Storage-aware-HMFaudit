package checkpoint

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"
)

func TestStateCommitmentUsesCanonicalSequenceAndRoots(t *testing.T) {
	locator := digest("locator")
	global := digest("global")
	got, err := StateCommitment(7, locator, global)
	if err != nil {
		t.Fatalf("state commitment: %v", err)
	}
	sequence := make([]byte, 8)
	binary.BigEndian.PutUint64(sequence, 7)
	input := append([]byte("STATE"), sequence...)
	input = append(input, locator[:]...)
	input = append(input, global[:]...)
	want := sha256.Sum256(input)
	if got != want {
		t.Fatalf("commitment = %x, want %x", got, want)
	}
	changed, _ := StateCommitment(8, locator, global)
	if changed == got {
		t.Fatal("changing the checkpoint sequence did not change the commitment")
	}
	if _, err := StateCommitment(0, locator, global); err == nil {
		t.Fatal("accepted checkpoint sequence zero")
	}
}

func TestServiceFinalizesAndPublishesCoordinatedRoots(t *testing.T) {
	snapshot := RootSnapshot{
		LocatorTreeID: "locator-main",
		LocatorRoot:   digest("locator-root"),
		GlobalHMFRoot: digest("global-root"),
	}
	source := &fixedSource{snapshot: snapshot}
	repository := newMemoryRepository()
	anchor := NewMockAnchor(100)
	baseTime := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	anchor.clock = func() time.Time { return baseTime.Add(time.Second) }
	service, err := NewService("test-system", source, anchor, repository)
	if err != nil {
		t.Fatalf("new checkpoint service: %v", err)
	}
	clockCalls := 0
	service.clock = func() time.Time {
		clockCalls++
		return baseTime.Add(time.Duration(clockCalls-1) * 2 * time.Second)
	}

	result, err := service.Finalize(context.Background())
	if err != nil {
		t.Fatalf("finalize checkpoint: %v", err)
	}
	if result.Sequence != 1 || result.Status != StatusFinalized {
		t.Fatalf("checkpoint sequence/status = %d/%s, want 1/%s",
			result.Sequence, result.Status, StatusFinalized)
	}
	if result.LocatorRoot != snapshot.LocatorRoot || result.GlobalHMFRoot != snapshot.GlobalHMFRoot {
		t.Fatal("checkpoint did not preserve the coordinated roots")
	}
	if result.Anchor == nil || result.Anchor.BlockHeight != 100 || result.Anchor.TransactionHash == "" {
		t.Fatalf("unexpected anchor receipt: %+v", result.Anchor)
	}
	if err := VerifyStateCommitment(result); err != nil {
		t.Fatalf("verify state commitment: %v", err)
	}
	if source.callCount() != 1 || anchor.CommitCount() != 1 {
		t.Fatalf("snapshot/anchor calls = %d/%d, want 1/1", source.callCount(), anchor.CommitCount())
	}
	if len(repository.events) != 2 || repository.events[0] != "pending:1" || repository.events[1] != "finalized:1" {
		t.Fatalf("repository events = %v, want pending before finalized", repository.events)
	}

	current, err := service.Current(context.Background())
	if err != nil {
		t.Fatalf("current checkpoint: %v", err)
	}
	if current.ID != result.ID || current.StateCommitment != result.StateCommitment {
		t.Fatalf("current checkpoint = %+v, want %+v", current, result)
	}
}

func TestServiceResumesPendingCheckpointAfterAnchorFailure(t *testing.T) {
	source := &fixedSource{snapshot: RootSnapshot{
		LocatorTreeID: "locator-main",
		LocatorRoot:   digest("locator-root"),
		GlobalHMFRoot: digest("global-root"),
	}}
	repository := newMemoryRepository()
	underlying := NewMockAnchor(10)
	anchor := &failOnceAnchor{next: underlying, failure: errors.New("mock chain unavailable")}
	service, err := NewService("test-system", source, anchor, repository)
	if err != nil {
		t.Fatalf("new checkpoint service: %v", err)
	}

	if _, err := service.Finalize(context.Background()); err == nil {
		t.Fatal("finalization succeeded while the anchor was unavailable")
	}
	pending, err := repository.LatestCheckpoint(context.Background(), "test-system")
	if err != nil {
		t.Fatalf("load pending checkpoint: %v", err)
	}
	if pending.Status != StatusPending || pending.Sequence != 1 {
		t.Fatalf("pending checkpoint = %+v", pending)
	}
	if _, err := repository.CurrentFinalized(context.Background(), "test-system"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("current finalized error = %v, want %v", err, ErrNotFound)
	}

	result, err := service.Finalize(context.Background())
	if err != nil {
		t.Fatalf("resume checkpoint: %v", err)
	}
	if result.Sequence != pending.Sequence || result.StateCommitment != pending.StateCommitment {
		t.Fatal("retry allocated a different checkpoint instead of resuming pending work")
	}
	if source.callCount() != 1 {
		t.Fatalf("coordinated snapshot count = %d, want 1", source.callCount())
	}
}

func TestServiceRecoversFinalityPointerAfterPublicationFailure(t *testing.T) {
	source := &fixedSource{snapshot: RootSnapshot{
		LocatorTreeID: "locator-main",
		LocatorRoot:   digest("locator-root"),
		GlobalHMFRoot: digest("global-root"),
	}}
	repository := newMemoryRepository()
	repository.failPublishAfterHistory = true
	anchor := NewMockAnchor(10)
	service, err := NewService("test-system", source, anchor, repository)
	if err != nil {
		t.Fatalf("new checkpoint service: %v", err)
	}

	if _, err := service.Finalize(context.Background()); err == nil {
		t.Fatal("finalization succeeded while publication was interrupted")
	}
	latest, err := repository.LatestCheckpoint(context.Background(), "test-system")
	if err != nil {
		t.Fatalf("load finalized history row: %v", err)
	}
	if latest.Status != StatusFinalized {
		t.Fatalf("history status = %s, want %s", latest.Status, StatusFinalized)
	}
	if _, err := repository.CurrentFinalized(context.Background(), "test-system"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("current finalized error = %v, want %v", err, ErrNotFound)
	}

	result, err := service.Finalize(context.Background())
	if err != nil {
		t.Fatalf("recover finality publication: %v", err)
	}
	if result.Sequence != 1 || result.StateCommitment != latest.StateCommitment {
		t.Fatal("publication recovery allocated a new checkpoint")
	}
	if source.callCount() != 1 || anchor.CommitCount() != 1 {
		t.Fatalf("snapshot/anchor calls = %d/%d, want 1/1", source.callCount(), anchor.CommitCount())
	}
}

func TestServiceSerializesConcurrentFinalization(t *testing.T) {
	source := &fixedSource{snapshot: RootSnapshot{
		LocatorTreeID: "locator-main",
		LocatorRoot:   digest("locator-root"),
		GlobalHMFRoot: digest("global-root"),
	}}
	repository := newMemoryRepository()
	anchor := NewMockAnchor(1)
	service, err := NewService("test-system", source, anchor, repository)
	if err != nil {
		t.Fatalf("new checkpoint service: %v", err)
	}

	const count = 12
	results := make(chan Checkpoint, count)
	errorsFound := make(chan error, count)
	var group sync.WaitGroup
	for range count {
		group.Add(1)
		go func() {
			defer group.Done()
			value, err := service.Finalize(context.Background())
			if err != nil {
				errorsFound <- err
				return
			}
			results <- value
		}()
	}
	group.Wait()
	close(results)
	close(errorsFound)
	for err := range errorsFound {
		t.Fatalf("concurrent finalization: %v", err)
	}
	sequences := make([]int, 0, count)
	for value := range results {
		sequences = append(sequences, int(value.Sequence))
	}
	sort.Ints(sequences)
	for index, sequence := range sequences {
		if sequence != index+1 {
			t.Fatalf("sequences = %v, want 1 through %d", sequences, count)
		}
	}
	if anchor.CommitCount() != count {
		t.Fatalf("anchor commit count = %d, want %d", anchor.CommitCount(), count)
	}
}

func TestServiceRejectsCorruptedPendingCheckpoint(t *testing.T) {
	repository := newMemoryRepository()
	commitment, _ := StateCommitment(1, digest("locator"), digest("global"))
	repository.checkpoints[1] = Checkpoint{
		ID: "bad", SystemID: "test-system", Sequence: 1, LocatorTreeID: "locator-main",
		LocatorRoot: digest("locator"), GlobalHMFRoot: digest("global"),
		StateCommitment: commitment, Status: StatusPending, CreatedAt: time.Now().UTC(),
	}
	repository.checkpoints[1] = func(value Checkpoint) Checkpoint {
		value.StateCommitment[0] ^= 0xff
		return value
	}(repository.checkpoints[1])
	service, err := NewService("test-system", &fixedSource{}, NewMockAnchor(1), repository)
	if err != nil {
		t.Fatalf("new checkpoint service: %v", err)
	}
	if _, err := service.Finalize(context.Background()); !errors.Is(err, ErrInvalidCheckpoint) {
		t.Fatalf("finalization error = %v, want %v", err, ErrInvalidCheckpoint)
	}
}

func TestMockAnchorIsIdempotent(t *testing.T) {
	anchor := NewMockAnchor(25)
	commitment := digest("commitment")
	first, err := anchor.Commit(context.Background(), commitment)
	if err != nil {
		t.Fatalf("first commit: %v", err)
	}
	second, err := anchor.Commit(context.Background(), commitment)
	if err != nil {
		t.Fatalf("second commit: %v", err)
	}
	if first != second || anchor.CommitCount() != 1 {
		t.Fatalf("mock anchor was not idempotent: first=%+v second=%+v count=%d",
			first, second, anchor.CommitCount())
	}
}

type fixedSource struct {
	mu       sync.Mutex
	snapshot RootSnapshot
	calls    int
}

func (source *fixedSource) Snapshot(ctx context.Context) (RootSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return RootSnapshot{}, err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	source.calls++
	return source.snapshot, nil
}

func (source *fixedSource) callCount() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.calls
}

type failOnceAnchor struct {
	mu      sync.Mutex
	next    Anchor
	failure error
}

func (anchor *failOnceAnchor) Commit(ctx context.Context,
	commitment [32]byte) (AnchorReceipt, error) {
	anchor.mu.Lock()
	if anchor.failure != nil {
		err := anchor.failure
		anchor.failure = nil
		anchor.mu.Unlock()
		return AnchorReceipt{}, err
	}
	anchor.mu.Unlock()
	return anchor.next.Commit(ctx, commitment)
}

type memoryRepository struct {
	mu                      sync.Mutex
	checkpoints             map[int64]Checkpoint
	current                 *Checkpoint
	events                  []string
	failPublishAfterHistory bool
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{checkpoints: make(map[int64]Checkpoint)}
}

func (repository *memoryRepository) LatestCheckpoint(_ context.Context,
	systemID string) (Checkpoint, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	var latest Checkpoint
	for _, value := range repository.checkpoints {
		if value.SystemID == systemID && value.Sequence > latest.Sequence {
			latest = cloneCheckpoint(value)
		}
	}
	if latest.Sequence == 0 {
		return Checkpoint{}, ErrNotFound
	}
	return latest, nil
}

func (repository *memoryRepository) CurrentFinalized(_ context.Context,
	systemID string) (Checkpoint, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.current == nil || repository.current.SystemID != systemID {
		return Checkpoint{}, ErrNotFound
	}
	return cloneCheckpoint(*repository.current), nil
}

func (repository *memoryRepository) SavePending(_ context.Context, value Checkpoint) (Checkpoint, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if existing, exists := repository.checkpoints[value.Sequence]; exists &&
		existing.StateCommitment != value.StateCommitment {
		return Checkpoint{}, errors.New("checkpoint sequence conflict")
	}
	if value.ID == "" {
		value.ID = "memory:" + formatSequence(value.Sequence)
	}
	repository.checkpoints[value.Sequence] = cloneCheckpoint(value)
	repository.events = append(repository.events, "pending:"+formatSequence(value.Sequence))
	return cloneCheckpoint(value), nil
}

func (repository *memoryRepository) PublishFinalized(_ context.Context, value Checkpoint) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	pending, exists := repository.checkpoints[value.Sequence]
	if !exists || pending.StateCommitment != value.StateCommitment {
		return errors.New("pending checkpoint not found")
	}
	copy := cloneCheckpoint(value)
	repository.checkpoints[value.Sequence] = copy
	if repository.failPublishAfterHistory {
		repository.failPublishAfterHistory = false
		return errors.New("mock finality pointer failure")
	}
	repository.current = &copy
	repository.events = append(repository.events, "finalized:"+formatSequence(value.Sequence))
	return nil
}

func cloneCheckpoint(value Checkpoint) Checkpoint {
	if value.Anchor != nil {
		anchor := *value.Anchor
		value.Anchor = &anchor
	}
	if value.FinalizedAt != nil {
		finalizedAt := *value.FinalizedAt
		value.FinalizedAt = &finalizedAt
	}
	return value
}

func formatSequence(value int64) string {
	if value == 0 {
		return "0"
	}
	buffer := [20]byte{}
	position := len(buffer)
	for value > 0 {
		position--
		buffer[position] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[position:])
}

func digest(value string) [32]byte {
	return sha256.Sum256([]byte(value))
}
