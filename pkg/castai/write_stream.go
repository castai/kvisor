package castai

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
)

var (
	errNoActiveStream = errors.New("no active stream")
)

func NewWriteStream[T, U any](ctx context.Context, createStreamFunc func(ctx context.Context) (grpc.ClientStream, error)) *WriteStream[T, U] {
	return &WriteStream[T, U]{
		rootCtx:          ctx,
		createStreamFunc: createStreamFunc,
	}
}

// WriteStream wraps grpc client stream and handles stream reopen in case of send errors.
type WriteStream[T, U any] struct {
	rootCtx               context.Context
	createStreamFunc      func(ctx context.Context) (grpc.ClientStream, error)
	activeStream          grpc.ClientStream
	activeStreamCtx       context.Context
	activeStreamCtxCancel context.CancelFunc
	wasOpened             bool

	ReopenDelay time.Duration
}

func (w *WriteStream[T, U]) Send(m T) error {
	if w.activeStream == nil {
		if err := w.open(); err != nil {
			return err
		}
	}

	if err := w.activeStream.SendMsg(m); err != nil {
		w.close()
		return err
	}
	return nil
}

func (w *WriteStream[T, U]) Recv(m T) error {
	if w.activeStream == nil {
		return errNoActiveStream
	}
	return w.activeStream.RecvMsg(m)
}

func (w *WriteStream[T, U]) Close() error {
	if w.activeStream == nil {
		return nil
	}
	err := w.activeStream.CloseSend()
	w.close()
	return err
}

func (w *WriteStream[T, U]) open() error {
	if w.wasOpened && w.ReopenDelay != 0 {
		time.Sleep(w.ReopenDelay)
	}
	var err error
	w.activeStreamCtx, w.activeStreamCtxCancel = context.WithCancel(w.rootCtx)
	w.activeStream, err = w.createStreamFunc(w.activeStreamCtx)
	if err != nil {
		w.close()
		return fmt.Errorf("open stream: %w", err)
	}
	w.wasOpened = true
	return nil
}

func (w *WriteStream[T, U]) close() {
	// To properly close active stream we can cancel it's context.
	// See https://github.com/grpc/grpc-go/blob/master/stream.go#L148
	if w.activeStreamCtxCancel != nil {
		w.activeStreamCtxCancel()
	}
	w.activeStreamCtx = nil
	w.activeStream = nil
}
