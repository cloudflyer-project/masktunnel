package masktunnel

import (
	"context"
	"sync"
	"time"
)

// This file provides small, gopy-friendly helpers for Python bindings.

// ========== Context helpers ==========

var (
	globalCtx    context.Context
	globalCancel context.CancelFunc
	globalOnce   sync.Once
)

// Background returns a process-wide background context.
func Background() context.Context {
	globalOnce.Do(func() {
		globalCtx, globalCancel = context.WithCancel(context.Background())
	})
	return globalCtx
}

// ContextWithCancel wraps a context and its cancel function.
type ContextWithCancel struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// NewContextWithCancel creates a new cancellable context.
func NewContextWithCancel() *ContextWithCancel {
	ctx, cancel := context.WithCancel(context.Background())
	return &ContextWithCancel{ctx: ctx, cancel: cancel}
}

// Cancel cancels the underlying context.
func (c *ContextWithCancel) Cancel() {
	if c != nil && c.cancel != nil {
		c.cancel()
	}
}

// Context returns the underlying context.
func (c *ContextWithCancel) Context() context.Context {
	if c == nil {
		return context.Background()
	}
	return c.ctx
}

// CancelGlobalContext cancels the global background context.
func CancelGlobalContext() {
	if globalCancel != nil {
		globalCancel()
	}
}

// NewContext returns a new background-derived context.
func NewContext() context.Context {
	ctx, _ := context.WithCancel(context.Background())
	return ctx
}

// ========== Time constants ==========

var (
	Nanosecond  = time.Nanosecond
	Microsecond = time.Microsecond
	Millisecond = time.Millisecond
	Second      = time.Second
	Minute      = time.Minute
	Hour        = time.Hour
)

// ParseDuration parses a duration string (e.g. "300ms", "2h45m").
func ParseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}
