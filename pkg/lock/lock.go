package chart

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/werf/lockgate"
	"github.com/werf/lockgate/pkg/file_locker"
	"github.com/werf/logboek"
)

var hostLocker lockgate.Locker

var (
	ErrNotAcquired = errors.New("lock is not acquired")
)

func HostLocker() (lockgate.Locker, error) {
	if hostLocker == nil {
		userHomeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("get user home dir: %w", err)
		}

		if locker, err := file_locker.NewFileLocker(filepath.Join(userHomeDir, ".werf", "service", "locks")); err != nil {
			return nil, fmt.Errorf("construct new file locker: %w", err)
		} else {
			hostLocker = locker
		}
	}

	return hostLocker, nil
}

func SetHostLocker(locker lockgate.Locker) {
	hostLocker = locker
}

func SetupLockerDefaultOptions(ctx context.Context, opts lockgate.AcquireOptions) lockgate.AcquireOptions {
	if opts.OnWaitFunc == nil {
		opts.OnWaitFunc = DefaultLockerOnWait(ctx)
	}
	if opts.OnLostLeaseFunc == nil {
		opts.OnLostLeaseFunc = DefaultLockerOnLostLease
	}
	return opts
}

func WithHostLock(ctx context.Context, lockName string, opts lockgate.AcquireOptions, f func() error) (errRes error) {
	hostLocker, err := HostLocker()
	if err != nil {
		return fmt.Errorf("get host locker: %w", err)
	}

	return lockgate.WithAcquire(hostLocker, lockName, SetupLockerDefaultOptions(ctx, opts), func(acquired bool) error {
		if !acquired {
			return ErrNotAcquired
		}
		return f()
	})
}

func AcquireHostLock(ctx context.Context, lockName string, opts lockgate.AcquireOptions) (bool, lockgate.LockHandle, error) {
	hostLocker, err := HostLocker()
	if err != nil {
		return false, lockgate.LockHandle{}, fmt.Errorf("get host locker: %w", err)
	}

	return hostLocker.Acquire(lockName, SetupLockerDefaultOptions(ctx, opts))
}

func ReleaseHostLock(lock lockgate.LockHandle) error {
	hostLocker, err := HostLocker()
	if err != nil {
		return fmt.Errorf("get host locker: %w", err)
	}

	return hostLocker.Release(lock)
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
