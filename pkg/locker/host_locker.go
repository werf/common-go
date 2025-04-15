package locker

import (
	"context"
	"fmt"
	"github.com/werf/lockgate"
	"github.com/werf/lockgate/pkg/file_locker"
	"github.com/werf/logboek"
)

type HostLocker struct {
	locker lockgate.Locker
}

func NewHostLocker(locksDir string) (*HostLocker, error) {
	locker, err := file_locker.NewFileLocker(locksDir)
	if err != nil {
		return nil, fmt.Errorf("unable to create file locker: %w", err)
	}
	return &HostLocker{locker: locker}, nil
}

func (hl *HostLocker) Locker() lockgate.Locker {
	return hl.locker
}

func (hl *HostLocker) AcquireLock(ctx context.Context, lockName string, opts lockgate.AcquireOptions) (bool, lockgate.LockHandle, error) {
	return hl.locker.Acquire(lockName, SetupDefaultOptions(ctx, opts))
}

func (hl *HostLocker) ReleaseLock(lock lockgate.LockHandle) error {
	return hl.locker.Release(lock)
}

// WithLock acquires host lock and executes callback opts.NonBlocking=false.
// Be aware, if opts.NonBlocking=true it does "try lock", ignores lock's status and executes callback anyway.
func (hl *HostLocker) WithLock(ctx context.Context, lockName string, opts lockgate.AcquireOptions, f func() error) error {
	return lockgate.WithAcquire(hl.locker, lockName, SetupDefaultOptions(ctx, opts), func(_ bool) error {
		return f()
	})
}

func SetupDefaultOptions(ctx context.Context, opts lockgate.AcquireOptions) lockgate.AcquireOptions {
	if opts.OnWaitFunc == nil {
		opts.OnWaitFunc = defaultOnWaitFunc(ctx)
	}
	if opts.OnLostLeaseFunc == nil {
		opts.OnLostLeaseFunc = defaultOnLostLeaseFunc
	}
	return opts
}

func defaultOnWaitFunc(ctx context.Context) func(lockName string, doWait func() error) error {
	return func(lockName string, doWait func() error) error {
		logProcessMsg := fmt.Sprintf("Waiting for locked %q", lockName)
		return logboek.Context(ctx).Info().LogProcessInline(logProcessMsg).DoError(doWait)
	}
}

func defaultOnLostLeaseFunc(lock lockgate.LockHandle) error {
	panic(fmt.Sprintf("Locker has lost lease for locked %q uuid %s. Will crash current process immediately!", lock.LockName, lock.UUID))
}
