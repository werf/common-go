package chart

import (
	"context"
	"errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/werf/lockgate"
)

var _ = Describe("lock", func() {
	Describe("WithHostLock", func() {
		It("should return err if lock is already acquired", func() {
			isCalledFirstCallback := false
			isCalledSecondCallback := false

			ctx := context.Background()
			lockName := "test"

			err := withHostLock(ctx, lockName, func() error {
				isCalledFirstCallback = true
				return withHostLock(ctx, lockName, func() error {
					isCalledSecondCallback = true
					return nil
				})
			})

			Expect(errors.Is(err, ErrNotAcquired)).To(BeTrue())
			Expect(isCalledFirstCallback).To(BeTrue())
			Expect(isCalledSecondCallback).To(BeFalse())
		})
	})
})

func withHostLock(ctx context.Context, lockName string, fn func() error) error {
	lockOptions := lockgate.AcquireOptions{NonBlocking: true}
	return WithHostLock(ctx, lockName, lockOptions, fn)
}
