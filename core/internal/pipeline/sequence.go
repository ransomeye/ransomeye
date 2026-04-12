package pipeline

import "sync/atomic"

var globalSeq atomic.Uint64

func NextSequence() uint64 {
	return globalSeq.Add(1)
}

func ResetSequencesForReplay() {
	globalSeq.Store(0)
	detectionSeq.Store(0)
}
