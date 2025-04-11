package graceful

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

var (
	terminationErrChan = make(chan terminationError, 1)

	cancelNotify context.CancelFunc
)

type terminationError struct {
	err      error
	exitCode int
}

// WithTermination returns a copy of parent context that is marked done when SIGINT or SIGTERM received.
func WithTermination(ctx context.Context) context.Context {
	var notifyCtx context.Context
	notifyCtx, cancelNotify = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	return notifyCtx
}

// Terminate starts termination if not yet. It should be called after WithTermination().
// It is safe for concurrent usage.
func Terminate(err error, exitCode int) {
	termErr := terminationError{
		err:      err,
		exitCode: exitCode,
	}

	// Unblocking write: write err in channel if channel is empty, otherwise just go next.
	select {
	case terminationErrChan <- termErr:
	default:
		// just go next in non-blocking mode
	}

	// If WithTermination() isn't called before we will have panic here.
	if cancelNotify != nil {
		cancelNotify()
	}
}

// IsTerminating returns true if termination is in progress. It is safe for concurrent usage.
func IsTerminating(ctx context.Context) bool {
	// Unblocking read
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

type ShutdownErrorCallback func(err error, exitCode int)

// Shutdown handles termination using terminationCtx. It should be called after WithTermination().
// If termination context is done, it ensures termination err using SIGTERM by default.
// If panic is happened, it translates the panic to termination err.
// If termination err is exists, it calls callback(msg, exitCode).
// Otherwise, it does nothing.
func Shutdown(ctx context.Context, callback ShutdownErrorCallback) {
	// Unblocking read
	select {
	case <-ctx.Done():
		// If ctx is done, we have to ensure termination err. We could use SIGTERM by default.
		Terminate(errors.New("process terminated"), 143) // SIGTERM exit code
	default:
		// just go next in non-blocking mode
	}

	// If we have panic; we should translate it to termination err.
	if r := recover(); r != nil {
		Terminate(fmt.Errorf("%v", r), 1)
	}

	// Unblocking read
	select {
	case termErr := <-terminationErrChan:
		// If termErr is exists, it calls the callback.
		callback(termErr.err, termErr.exitCode)
	default:
		// just go next in non-blocking mode
	}
}
