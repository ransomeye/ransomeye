package ack

import (
	"errors"
	"sync"
)

type State uint8

const (
	StateSuccess State = iota + 1
	StateFailure
)

type Result struct {
	State State
	Err   error
}

type Metadata struct {
	ReplayKey     string
	MessageID     string
	ContentSHA256 [32]byte
}

type observerFunc func(Metadata, Result)

type entry struct {
	meta     Metadata
	waiters  []chan Result
	resolved *Result
}

type Controller struct {
	mu       sync.Mutex
	entries  map[string]*entry
	observer observerFunc
}

func NewController() *Controller {
	return &Controller{entries: make(map[string]*entry)}
}

func (c *Controller) SetObserver(fn func(Metadata, Result)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.observer = fn
}

func (c *Controller) Wait(meta Metadata) Result {
	waiter, resolved := c.watch(meta)
	if resolved != nil {
		return *resolved
	}
	return <-waiter
}

func (c *Controller) watch(meta Metadata) (chan Result, *Result) {
	if meta.ReplayKey == "" {
		res := failureResult(errors.New("replay key missing"))
		return nil, &res
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[meta.ReplayKey]
	if !ok {
		e = &entry{meta: meta}
		c.entries[meta.ReplayKey] = e
	}
	if e.meta.MessageID != "" && meta.MessageID != "" && e.meta.MessageID != meta.MessageID {
		res := failureResult(errors.New("message_id mismatch"))
		return nil, &res
	}
	if e.meta.ContentSHA256 != ([32]byte{}) && meta.ContentSHA256 != ([32]byte{}) && e.meta.ContentSHA256 != meta.ContentSHA256 {
		res := failureResult(errors.New("content hash mismatch"))
		return nil, &res
	}
	if e.meta.MessageID == "" {
		e.meta.MessageID = meta.MessageID
	}
	if e.meta.ContentSHA256 == ([32]byte{}) {
		e.meta.ContentSHA256 = meta.ContentSHA256
	}
	if e.resolved != nil {
		resolved := *e.resolved
		return nil, &resolved
	}
	ch := make(chan Result, 1)
	e.waiters = append(e.waiters, ch)
	return ch, nil
}

func (c *Controller) Commit(meta Metadata) {
	c.resolve(meta, successResult())
}

func (c *Controller) Fail(meta Metadata, err error) {
	c.resolve(meta, failureResult(err))
}

func (c *Controller) resolve(meta Metadata, result Result) {
	if c == nil || meta.ReplayKey == "" {
		return
	}
	var (
		waiters  []chan Result
		observer observerFunc
	)
	c.mu.Lock()
	e, ok := c.entries[meta.ReplayKey]
	if !ok {
		if result.State == StateSuccess {
			c.entries[meta.ReplayKey] = &entry{
				meta:     meta,
				resolved: &result,
			}
		}
		observer = c.observer
		c.mu.Unlock()
		if observer != nil {
			observer(meta, result)
		}
		return
	}
	if e.meta.MessageID == "" {
		e.meta.MessageID = meta.MessageID
	}
	if e.meta.ContentSHA256 == ([32]byte{}) {
		e.meta.ContentSHA256 = meta.ContentSHA256
	}
	waiters = append(waiters, e.waiters...)
	e.waiters = nil
	if result.State == StateSuccess {
		e.resolved = &result
	} else {
		delete(c.entries, meta.ReplayKey)
	}
	observer = c.observer
	c.mu.Unlock()

	for _, waiter := range waiters {
		waiter <- result
		close(waiter)
	}
	if observer != nil {
		observer(e.meta, result)
	}
}

func (c *Controller) Metadata(replayKey string) (Metadata, bool) {
	if c == nil || replayKey == "" {
		return Metadata{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[replayKey]
	if !ok {
		return Metadata{}, false
	}
	return e.meta, true
}

func (c *Controller) PendingReplayKeys() []string {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.entries))
	for replayKey, e := range c.entries {
		if e.resolved != nil {
			continue
		}
		out = append(out, replayKey)
	}
	return out
}

func successResult() Result {
	return Result{State: StateSuccess}
}

func failureResult(err error) Result {
	if err == nil {
		err = errors.New("ack failure")
	}
	return Result{
		State: StateFailure,
		Err:   err,
	}
}
