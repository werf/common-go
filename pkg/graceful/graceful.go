package graceful

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

type terminationContextKey string

var (
	terminationKey = terminationContextKey("graceful_termination")
)

type termination struct {
	ctx    context.Context
	cancel context.CancelFunc

	errChan chan terminationError
}

// doWithError adds termination error and cancels context.
// It is safe for concurrent usage.
func (t *termination) doWithError(termErr terminationError) {
	// Unblocking write: write err in channel if channel is empty, otherwise just go next.
	select {
	case t.errChan <- termErr:
	default:
		// just go next in non-blocking mode
	}
	// Cancel context if it is not cancelled yet.
	t.cancel()
}

type terminationError struct {
	err      error
	exitCode int
}

// WithTermination returns a termination that is marked done
// when SIGINT or SIGTERM received or Terminate() called.
func WithTermination(ctx context.Context) context.Context {
	notifyCtx, cancelNotify := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	return context.WithValue(notifyCtx, terminationKey, &termination{
		ctx:     notifyCtx,
		cancel:  cancelNotify,
		errChan: make(chan terminationError, 1),
	})
}

// Terminate starts termination if not yet. ctx must be the context created WithTermination().
// It is safe for concurrent usage.
func Terminate(ctx context.Context, err error, exitCode int) {
	term, ok := ctx.Value(terminationKey).(*termination)
	if !ok {
		panic("context is not termination")
	}

	term.doWithError(terminationError{
		err:      err,
		exitCode: exitCode,
	})
}

// IsTerminationContext returns "true" if ctx is termination.
func IsTerminationContext(ctx context.Context) bool {
	_, ok := ctx.Value(terminationKey).(*termination)
	return ok
}

// IsTerminating returns true if termination is in progress. ctx must be the context created WithTermination().
// It is safe for concurrent usage.
func IsTerminating(ctx context.Context) bool {
	term, ok := ctx.Value(terminationKey).(*termination)
	// If Done is not yet closed, Err returns nil. If Done is closed, Err returns a non-nil error explaining why.
	return ok && term.ctx.Err() != nil
}

type ShutdownErrorCallback func(err error, exitCode int)

// Shutdown handles termination using terminationCtx. ctx must be the context created WithTermination().
// If termination context is done, it ensures termination err using SIGTERM by default.
// If panic is happened, it translates the panic to termination err.
// If termination err is exists, it calls callback(msg, exitCode).
// Otherwise, it does nothing.
func Shutdown(ctx context.Context, callback ShutdownErrorCallback) {
	term, ok := ctx.Value(terminationKey).(*termination)
	if !ok {
		panic("context is not termination")
	}

	if IsTerminating(ctx) {
		// Ensure termination err. We could use SIGTERM by default.
		Terminate(ctx, errors.New("process terminated"), 143) // SIGTERM exit code
	}

	// Translate panic to termination err if needed.
	if r := recover(); r != nil {
		Terminate(ctx, fmt.Errorf("%v", r), 1)
	}

	// Unblocking read
	select {
	case termErr := <-term.errChan:
		// If termErr is exists, it calls the callback.
		callback(termErr.err, termErr.exitCode)
	default:
		// just go next in non-blocking mode
	}
}
