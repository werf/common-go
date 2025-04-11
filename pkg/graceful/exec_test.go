package graceful

import (
	"context"
	"errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("graceful exec", func() {
	Describe("WrapCommand()", func() {
		It("returns cmd wrapped with graceful", func(ctx SpecContext) {
			cmd0 := ExecCommandContext(ctx, "echo", "test")
			Expect(cmd0).To(BeAssignableToTypeOf(&Cmd{}))
		})
	})
	Describe("errorHandler()", func() {
		It("should do nothing if ctx != context.Canceled", func(ctx SpecContext) {
			err0 := errors.New("some err")
			Expect(errorHandler(ctx, err0, false)).To(Equal(err0))
			Expect(terminationErrChan).To(HaveLen(0))
		})
		It("should terminate if ctx != context.Canceled and anyContext=true", func(ctx SpecContext) {
			err0 := errors.New("some err")
			Expect(errorHandler(ctx, err0, true)).To(Equal(err0))
			Expect(terminationErrChan).To(Receive(Equal(terminationError{
				err:      err0,
				exitCode: 1,
			})))
		})
		It("should terminate err if exitErr.Success()=false", func(ctx context.Context) {
			ctx0, cancel := context.WithCancel(ctx)

			cmd0 := ExecCommandContext(ctx0, "sleep", "5")
			Expect(cmd0.Start()).To(Succeed())

			cancel()
			exitErr := cmd0.Wait()

			Expect(errors.Is(ctx0.Err(), context.Canceled)).To(BeTrue())
			Expect(exitErr).NotTo(Succeed())

			Expect(errorHandler(ctx0, exitErr, false)).To(Equal(exitErr))
			Expect(terminationErrChan).To(Receive(Equal(terminationError{
				err:      exitErr,
				exitCode: -1,
			})))
		})
	})
})
