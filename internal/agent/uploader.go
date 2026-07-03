package agent

import (
	"context"
	"errors"
	"math/rand"
	"time"

	"github.com/arhuman/prooflog/internal/api"
	"github.com/arhuman/prooflog/internal/segment"
)

// runUploader drains the seal queue, uploading each segment to the store with
// exponential backoff plus jitter. It never advances past an un-ACKed segment,
// so replay resumes exactly from the last ACK. The first failure of an outage
// emits system.network_outage; draining the backlog emits system.replay_completed
// (REQ-E-04, §6).
func (a *Agent) runUploader() {
	defer close(a.uploaderDone)
	for {
		select {
		case <-a.stopUploader:
			a.drainRemaining()
			return
		case sealed := <-a.uploadCh:
			a.uploadWithRetry(a.uploadCtx, sealed)
		}
	}
}

// drainRemaining uploads whatever is still buffered at shutdown, bounded by the
// upload context (cancelled by Stop after drainTimeout). Anything left stays in
// the spool for replay.
func (a *Agent) drainRemaining() {
	for {
		select {
		case sealed := <-a.uploadCh:
			if !a.uploadWithRetry(a.uploadCtx, sealed) {
				return // upload context cancelled: give up, spool will replay
			}
		default:
			return
		}
	}
}

// uploadWithRetry uploads one segment, retrying until success or ctx is done.
// It returns false only when ctx was cancelled.
func (a *Agent) uploadWithRetry(ctx context.Context, sealed segment.Sealed) bool {
	backoff := backoffInitial
	for {
		err := a.uploadOnce(ctx, sealed)
		if err == nil {
			if err := a.spool.MarkAcked(sealed.SeqLast); err != nil {
				a.log.Error("mark acked", "err", err)
			}
			a.lastUploadedSeq.Store(sealed.SeqLast)
			a.lastAckSeq.Store(sealed.SeqLast)
			a.maybeEndOutage(sealed.SeqLast)
			return true
		}
		if ctx.Err() != nil {
			return false
		}
		a.beginOutage()
		a.log.Warn("segment upload failed, backing off",
			"segment", sealed.ID.String(), "seq_last", sealed.SeqLast,
			"backoff", backoff, "err", err)
		if !sleepCtx(ctx, jitter(backoff)) {
			return false
		}
		backoff *= 2
		if backoff > backoffMax {
			backoff = backoffMax
		}
	}
}

// uploadOnce streams one segment (meta header then frames read back from the
// spool as exact bytes) and waits for the store's ACK.
func (a *Agent) uploadOnce(ctx context.Context, sealed segment.Sealed) error {
	stream, err := a.storeClient.UploadSegment(ctx)
	if err != nil {
		return err
	}
	meta := &api.SegmentMeta{
		SegmentId:  sealed.ID.String(),
		SourceId:   a.cfg.SourceID,
		SeqFirst:   sealed.SeqFirst,
		SeqLast:    sealed.SeqLast,
		Root:       sealed.Root[:],
		Checkpoint: sealed.Checkpoint,
	}
	if err := stream.Send(&api.UploadRequest{Kind: &api.UploadRequestMeta{Meta: meta}}); err != nil {
		return err
	}

	it, err := a.spool.Iter(sealed.SeqFirst)
	if err != nil {
		return err
	}
	defer it.Close()
	for {
		rec, ok, err := it.Next()
		if err != nil {
			return err
		}
		if !ok || rec.Seq > sealed.SeqLast {
			break
		}
		h := rec.Hash()
		frame := &api.Frame{RecordBytes: rec.Bytes(), RecordHash: h[:]}
		if err := stream.Send(&api.UploadRequest{Kind: &api.UploadRequestFrame{Frame: frame}}); err != nil {
			return err
		}
	}
	_, err = stream.CloseAndRecv()
	return err
}

func (a *Agent) beginOutage() {
	if a.inOutage.CompareAndSwap(false, true) {
		a.outageStartAck.Store(a.lastAckSeq.Load())
		a.log.Warn("network outage: store unreachable, buffering locally")
		a.emitSystem("system.network_outage", map[string]any{
			"last_ack_seq": a.outageStartAck.Load(),
		})
	}
}

// maybeEndOutage closes an outage once the backlog is fully drained, recording
// how many events were buffered and replayed.
func (a *Agent) maybeEndOutage(ackedSeq uint64) {
	if !a.inOutage.Load() || len(a.uploadCh) > 0 {
		return
	}
	if a.inOutage.CompareAndSwap(true, false) {
		start := a.outageStartAck.Load()
		a.log.Info("replay completed", "from_seq", start+1, "to_seq", ackedSeq)
		a.emitSystem("system.replay_completed", map[string]any{
			"from_seq":        start + 1,
			"to_seq":          ackedSeq,
			"replayed_events": ackedSeq - start,
		})
	}
}

// runCheckpointer submits sealed-segment checkpoints to the verifier (directly)
// and the store (opportunistic forward), best-effort with a short timeout.
func (a *Agent) runCheckpointer(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case sealed := <-a.checkpointCh:
			note := &api.SignedNote{Note: sealed.Checkpoint, SourceId: a.cfg.SourceID, Origin: a.origin}
			if a.verifierClient != nil {
				a.submitCheckpoint(ctx, "verifier", func(c context.Context) error {
					_, err := a.verifierClient.SubmitCheckpoint(c, note)
					return err
				})
			}
			a.submitCheckpoint(ctx, "store", func(c context.Context) error {
				_, err := a.storeClient.SubmitCheckpoint(c, note)
				return err
			})
		}
	}
}

func (a *Agent) submitCheckpoint(ctx context.Context, target string, fn func(context.Context) error) {
	cctx, cancel := context.WithTimeout(ctx, submitTimeout)
	defer cancel()
	if err := fn(cctx); err != nil && !errors.Is(err, context.Canceled) {
		a.log.Debug("checkpoint submit failed", "target", target, "err", err)
	}
}

func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	// full jitter: random in [d/2, d].
	return d/2 + time.Duration(rand.Int63n(int64(d/2)+1))
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
