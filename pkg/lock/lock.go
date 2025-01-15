package chart

import (
	"context"
	"fmt"

	"github.com/werf/lockgate"
	"github.com/werf/logboek"
)

// FIXME(ilya-lesikov): init this in Nelm/helm too
var HostLocker lockgate.Locker

func SetupLockerDefaultOptions(ctx context.Context, opts lockgate.AcquireOptions) lockgate.AcquireOptions {
	if opts.OnWaitFunc == nil {
		opts.OnWaitFunc = DefaultLockerOnWait(ctx)
	}
	if opts.OnLostLeaseFunc == nil {
		opts.OnLostLeaseFunc = DefaultLockerOnLostLease
	}
	return opts
}

func WithHostLock(ctx context.Context, lockName string, opts lockgate.AcquireOptions, f func() error) error {
	return lockgate.WithAcquire(HostLocker, lockName, SetupLockerDefaultOptions(ctx, opts), func(_ bool) error {
		return f()
	})
}

func AcquireHostLock(ctx context.Context, lockName string, opts lockgate.AcquireOptions) (bool, lockgate.LockHandle, error) {
	return HostLocker.Acquire(lockName, SetupLockerDefaultOptions(ctx, opts))
}

func ReleaseHostLock(lock lockgate.LockHandle) error {
	return HostLocker.Release(lock)
}

func DefaultLockerOnWait(ctx context.Context) func(lockName string, doWait func() error) error {
	return func(lockName string, doWait func() error) error {
		logProcessMsg := fmt.Sprintf("Waiting for locked %q", lockName)
		return logboek.Context(ctx).Info().LogProcessInline(logProcessMsg).DoError(doWait)
	}
}

func DefaultLockerOnLostLease(lock lockgate.LockHandle) error {
	panic(fmt.Sprintf("Locker has lost lease for locked %q uuid %s. Will crash current process immediately!", lock.LockName, lock.UUID))
}
