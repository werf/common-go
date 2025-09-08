package graceful

import (
	"context"
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
	cancel context.CancelFunc

	descChan chan TerminationDescriptor
}

// run adds termination descriptor and cancels context.
// It is safe for concurrent usage.
func (t *termination) run(desc TerminationDescriptor) {
	// Unblocking write: write err in channel if channel is empty, otherwise just go next.
	select {
	case t.descChan <- desc:
	default:
		// just go next in non-blocking mode
	}
	// Cancel context if it is not cancelled yet.
	t.cancel()
}

// listenSystemSignals
// Blocks until ctx is done or system signal (SIGINT, SIGTERM) is received.
// If system signal is received, it starts termination process translating the signal to TerminationDescriptor.
// When it unblocks it resets system signal handler.
func (t *termination) listenSystemSignals(ctx context.Context) {
	listenedSignals := []os.Signal{os.Interrupt, syscall.SIGTERM}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, listenedSignals...)

	// Block until ctx is done or signal received.
	select {
	case <-ctx.Done():
		// do nothing
	case sig := <-sigChan:
		t.run(TerminationDescriptor{
			err:      nil,
			exitCode: int(sig.(syscall.Signal)) + 128,
			signal:   sig,
		})
	}

	signal.Reset(listenedSignals...)
}

type TerminationDescriptor struct {
	err      error
	exitCode int
	signal   os.Signal
}

func (t TerminationDescriptor) Err() error {
	return t.err
}

func (t TerminationDescriptor) Signal() os.Signal {
	return t.signal
}

func (t TerminationDescriptor) ExitCode() int {
	return t.exitCode
}

// WithTermination returns a termination context that is marked done
// when SIGINT or SIGTERM received or Terminate() called.
func WithTermination(ctx context.Context) context.Context {
	newCtx, newStop := context.WithCancel(ctx)
	term := &termination{
		cancel:   newStop,
		descChan: make(chan TerminationDescriptor, 1),
	}
	go term.listenSystemSignals(newCtx)
	return context.WithValue(newCtx, terminationKey, term)
}

// Terminate starts termination if not yet. ctx must be the context created WithTermination().
// It is safe for concurrent usage.
func Terminate(ctx context.Context, err error, exitCode int) {
	term, ok := ctx.Value(terminationKey).(*termination)
	if !ok {
		panic("context is not termination context")
	}

	term.run(TerminationDescriptor{
		err:      err,
		exitCode: exitCode,
		signal:   nil,
	})
}

// IsTerminationContext returns "true" if ctx is termination one.
// It is safe for concurrent usage.
func IsTerminationContext(ctx context.Context) bool {
	_, ok := ctx.Value(terminationKey).(*termination)
	return ok
}

// IsTerminating returns true if termination is in progress. ctx must be the context created WithTermination().
// It is safe for concurrent usage.
func IsTerminating(ctx context.Context) bool {
	term, ok := ctx.Value(terminationKey).(*termination)
	return ok && len(term.descChan) > 0
}

type ShutdownCallback func(ctx context.Context, desc TerminationDescriptor)

// Shutdown handles termination using terminationCtx. ctx must be the context created WithTermination().
// Callback is always called.
func Shutdown(ctx context.Context, callback ShutdownCallback) {
	term, ok := ctx.Value(terminationKey).(*termination)
	if !ok {
		panic("context is not termination")
	}

	// Translate panic to termination if needed.
	if r := recover(); r != nil {
		Terminate(ctx, fmt.Errorf("%v", r), 1)
	}

	// Unblocking read
	select {
	case desc := <-term.descChan:
		// If TermDesc is exists, pass it to callback.
		callback(ctx, desc)
	default:
		// If desc is not exists, pass default desc to callback.
		callback(ctx, TerminationDescriptor{})
	}
}
