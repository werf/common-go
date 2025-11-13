package locker_with_retry

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/werf/lockgate"
	"github.com/werf/logboek"
)

type LockerWithRetry struct {
	Locker  lockgate.Locker
	Options LockerWithRetryOptions
	Ctx     context.Context
}

type LockerWithRetryOptions struct {
	MaxAcquireAttempts int
	MaxReleaseAttempts int
	CustomLogWarnFunc  func(msg string)
	CustomLogErrFunc   func(msg string)
}

func NewLockerWithRetry(ctx context.Context, locker lockgate.Locker, opts LockerWithRetryOptions) *LockerWithRetry {
	return &LockerWithRetry{Locker: locker, Options: opts, Ctx: ctx}
}

func (locker *LockerWithRetry) Acquire(lockName string, opts lockgate.AcquireOptions) (acquired bool, handle lockgate.LockHandle, err error) {
	executeWithRetry(locker.Ctx, locker.Options.MaxAcquireAttempts, func() error {
		acquired, handle, err = locker.Locker.Acquire(lockName, opts)
		if err != nil {
			msg := fmt.Sprintf("ERROR: unable to acquire lock %s: %s\n", lockName, err)
			if locker.Options.CustomLogErrFunc != nil {
				locker.Options.CustomLogErrFunc(msg)
			} else {
				logboek.Context(locker.Ctx).Error().LogF(msg)
			}
		}
		return err
	}, locker.Options)

	return
}

func (locker *LockerWithRetry) Release(lock lockgate.LockHandle) (err error) {
	executeWithRetry(locker.Ctx, locker.Options.MaxAcquireAttempts, func() error {
		err = locker.Locker.Release(lock)
		if err != nil {
			msg := fmt.Sprintf("ERROR: unable to release lock %s %s: %s\n", lock.UUID, lock.LockName, err)
			if locker.Options.CustomLogErrFunc != nil {
				locker.Options.CustomLogErrFunc(msg)
			} else {
				logboek.Context(locker.Ctx).Error().LogF(msg)
			}
		}
		return err
	}, locker.Options)

	return
}

func executeWithRetry(ctx context.Context, maxAttempts int, executeFunc func() error, opts LockerWithRetryOptions) {
	attempt := 1

executeAttempt:
	if err := executeFunc(); err != nil {
		if attempt == maxAttempts {
			return
		}

		seconds := rand.Intn(10) // from 0 to 10 seconds
		msg := fmt.Sprintf("Retrying in %d seconds (%d/%d) ...\n", seconds, attempt, maxAttempts)
		if opts.CustomLogWarnFunc != nil {
			opts.CustomLogWarnFunc(msg)
		} else {
			logboek.Context(ctx).Warn().LogF(msg)
		}
		time.Sleep(time.Duration(seconds) * time.Second)

		attempt += 1
		goto executeAttempt
	}
}
