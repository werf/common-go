package graceful

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
)

type Cmd struct {
	*exec.Cmd

	ctx context.Context

	gracefulAnyContext bool
}

// GracefulAnyContext
// By default the graceful termination error handler applies only for context.Canceled contexts.
// To change the default behaviour and apply graceful termination error handler
// for any contexts, set cmd.GracefulAnyContext(true).
func (c *Cmd) GracefulAnyContext(flag bool) {
	c.gracefulAnyContext = flag
}

// Run works as usual but handles error with graceful termination error handler.
func (c *Cmd) Run() error {
	return errorHandler(c.ctx, c.Cmd.Run(), c.gracefulAnyContext)
}

// Wait works as usual but handles error with graceful termination error handler.
func (c *Cmd) Wait() error {
	return errorHandler(c.ctx, c.Cmd.Wait(), c.gracefulAnyContext)
}

// CombinedOutput works as usual but handles error with graceful termination error handler.
func (c *Cmd) CombinedOutput() ([]byte, error) {
	b, err := c.Cmd.CombinedOutput()
	return b, errorHandler(c.ctx, err, c.gracefulAnyContext)
}

func errorHandler(ctx context.Context, err error, anyContext bool) error {
	if !errors.Is(ctx.Err(), context.Canceled) {
		if !anyContext {
			return err
		}
	}

	var exitErr *exec.ExitError

	if errors.As(err, &exitErr) {
		if !exitErr.Success() {
			Terminate(exitErr, exitErr.ExitCode())
		}
	} else {
		Terminate(err, 1)
	}

	return err
}

// ExecCommandContext returns cmd is wrapped with graceful termination behaviour.
// It overrides cmd.Cancel() function to send SIGTERM to cmd process instead of SIGKILL.
// It adds graceful termination error handler for cmd.Wait(), cmd.Run() and cmd.CombinedOutput().
//
// By default the graceful termination error handler applies only for context.Canceled contexts.
// To change the default behaviour and apply graceful termination error handler
// for any contexts, set cmd.GracefulAnyContext(true).
func ExecCommandContext(ctx context.Context, name string, arg ...string) *Cmd {
	newCmd := &Cmd{
		Cmd: exec.CommandContext(ctx, name, arg...),
		ctx: ctx,
	}
	// Override cancel function to replace SIGKILL with SIGTERM
	newCmd.Cancel = func() error {
		return newCmd.Process.Signal(syscall.SIGTERM)
	}

	return newCmd
}
