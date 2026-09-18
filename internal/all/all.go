package all

import (
	"context"
	"fmt"
	"sync"
)

const LocatorTreeID = "ALL"

type LocatorRequest struct {
	Key   LocatorKey
	Value LocatorValue
}

type ALL struct {
	TreeID         string
	LocatorTree    *LocatorTree
	Order          int
	PagesPerBucket int64

	requests chan LocatorRequest
	updates  chan LocatorUpdate
	stop     chan struct{}
	done     chan struct{}

	workerMu sync.Mutex
	running  bool
	stopped  bool
}

func NewALL(order int, pagesPerBucket int64) (*ALL, error) {
	if order < 3 {
		return nil, fmt.Errorf("new ALL: order must be at least 3")
	}
	if pagesPerBucket <= 0 {
		return nil, fmt.Errorf("new ALL: pages per bucket must be positive")
	}

	return &ALL{
		TreeID:         LocatorTreeID,
		LocatorTree:    NewLocatorTree(order),
		Order:          order,
		PagesPerBucket: pagesPerBucket,

		requests: make(chan LocatorRequest, 1024),
		updates:  make(chan LocatorUpdate, 256),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}, nil
}

// Submit queues one logical-to-physical mapping from HM.
func (all *ALL) Submit(request LocatorRequest) error {
	select {
	case all.requests <- request: //receive a request into channel
		return nil
	case <-all.stop:
		return fmt.Errorf("submit ALL: worker stopped")
	case <-all.done:
		return fmt.Errorf("submit ALL: worker stopped")
	}
}

func (all *ALL) Updates() <-chan LocatorUpdate {
	return all.updates //return updates channel
}

// Run processes requests serially because every request mutates one tree.
func (all *ALL) Run(ctx context.Context) {
	all.workerMu.Lock()
	if all.running || all.stopped {
		all.workerMu.Unlock()
		return
	}
	all.running = true
	all.workerMu.Unlock()

	defer func() { //when ALL is terminated
		all.workerMu.Lock()
		all.running = false
		all.stopped = true
		all.workerMu.Unlock()
		close(all.done)
	}()

	for {
		select {
		case <-ctx.Done(): //when ALL get terminated
			return
		case <-all.stop: //when ALl called Stop
			return
		case request := <-all.requests: //request comes in
			update := all.LocatorTree.InsertWithUpdate(
				request.Key,
				&request.Value,
				all.LocatorTree.RootPage,
			)

			all.updates <- update //insert update into updates channel for persistence later
		}
	}
}

func (all *ALL) Stop(ctx context.Context) error {
	all.workerMu.Lock()
	if !all.stopped {
		all.stopped = true
		close(all.stop) //close all
	}
	running := all.running
	all.workerMu.Unlock()

	if !running {
		return nil
	}

	select { //in case still running a process
	case <-all.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
