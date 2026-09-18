package hm

import (
	"fmt"
	"time"

	"github.com/SirojWongpitakroj/hmf-audit/internal/domain"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hmf"
)

type appendRequest struct {
	Log    domain.Log
	Result chan error // for ack with caller
}

func (hm *Manager) runSegmentWorker(
	regionID string,
	shardID int64,
	requests <-chan appendRequest,
	updates chan<- hmf.HMFUpdate,
	stop <-chan struct{}) {

	var active *activeSegment
	var timer *time.Timer
	var timerC <-chan time.Time
	stopTimer := func() {
		if timer != nil {
			timer.Stop()
			timer = nil
			timerC = nil
		}
	}

	openSegment := func() error {
		_, err := hm.openSegment(regionID, shardID, hm.nextSegmentID(regionID, shardID))
		if err != nil {
			return err
		}

		active, err = hm.getActiveSegment(regionID, shardID)
		if err != nil {
			return err
		}

		timer = time.NewTimer(hm.SegmentDuration)
		timerC = timer.C
		return nil
	}

	closeSegment := func() error {
		if active == nil {
			return nil
		}

		update, err := hm.closeSegment(regionID, shardID)
		if err != nil {
			return err
		}

		updates <- update
		stopTimer()
		active = nil
		return nil
	}

	defer stopTimer()

	//main section code
	for {
		select {
		case <-stop:
			if active != nil && active.Tree.LeafCount > 0 {
				_ = closeSegment()
			}
			return
		case request, open := <-requests: //from log source
			if !open {
				if active != nil && active.Tree.LeafCount > 0 {
					_ = closeSegment() // the channel is disconnected
				}
				return
			}
			if request.Log.EventTime.IsZero() {
				request.Result <- fmt.Errorf("append request: event time is required")
				continue
			}
			//no active segment yet
			if active == nil {
				if err := openSegment(); err != nil {
					request.Result <- err //ack
					continue
				}
			}

			//exist active segment and full
			if active.Tree.LeafCount >= int64(active.Tree.MaxLeaves) {
				if err := closeSegment(); err != nil {
					request.Result <- err
					continue
				}
				if err := openSegment(); err != nil {
					request.Result <- err
					continue
				}
			}
			leafID := active.Tree.LeafCount
			if err := active.Tree.Append(request.Log.Digest); err != nil {
				request.Result <- err
				continue
			}
			if active.StartedAt.IsZero() {
				active.StartedAt = request.Log.EventTime
			}
			active.EndedAt = request.Log.EventTime
			if err := hm.propagateToALL(request.Log, active.Tree, leafID); err != nil {
				request.Result <- err
				continue
			}
			request.Result <- nil
		case sealedAt := <-timerC: //timer is up
			active.SealedAt = sealedAt
			if err := closeSegment(); err != nil {
				continue
			}
			if err := openSegment(); err != nil {
				continue
			}
		}
	}
}
