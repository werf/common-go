package graceful

import (
	"context"
	"errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var _ = Describe("graceful core", func() {
	Describe("WithTermination()", func() {
		It("should return terminationCtx", func(ctx SpecContext) {
			terminationCtx := WithTermination(ctx)
			expectedCtx, stop := signal.NotifyContext(ctx, os.Interrupt)
			Expect(terminationCtx).To(BeAssignableToTypeOf(expectedCtx))
			stop()
			signal.Reset(os.Interrupt, syscall.SIGTERM)
		})
	})
	Describe("Terminate()", func() {
		It("should not panic if called before WithTermination()", func() {
			cancelNotify = nil
			err0 := errors.New("some err")

			Terminate(err0, 1)

			Expect(terminationErrChan).To(Receive(Equal(terminationError{
				err:      err0,
				exitCode: 1,
			})))
		})
		It("should work for single usage", func(ctx SpecContext) {
			_ = WithTermination(ctx)
			err0 := errors.New("some err")
			Terminate(err0, 1)
			Expect(terminationErrChan).To(Receive(Equal(terminationError{
				err:      err0,
				exitCode: 1,
			})))
		})
		It("should do FIFO for sequential double usage", func(ctx SpecContext) {
			_ = WithTermination(ctx)
			err0 := errors.New("some err")
			err1 := errors.New("another err")
			Terminate(err0, 1)
			Terminate(err1, 2)
			Expect(terminationErrChan).To(Receive(Equal(terminationError{
				err:      err0,
				exitCode: 1,
			})))
		})
		It("should be safe for concurrent usage", func(ctx SpecContext) {
			_ = WithTermination(ctx)

			err0 := errors.New("some err")
			err1 := errors.New("another err")

			wg := sync.WaitGroup{}
			wg.Add(2)
			go func() {
				defer wg.Done()
				Terminate(err0, 1)
			}()
			go func() {
				defer wg.Done()
				Terminate(err1, 2)
			}()
			wg.Wait()

			Expect(terminationErrChan).To(HaveLen(1))
		})
	})
	Describe("IsTerminating()", func() {
		It("should return 'false' if ctx is not done", func(ctx SpecContext) {
			Expect(IsTerminating(ctx)).To(BeFalse())
		})
		It("should return 'true' if ctx is not done", func(ctx SpecContext) {
			ctx0, cancel := context.WithCancel(ctx)
			cancel()
			Expect(IsTerminating(ctx0)).To(BeTrue())
		})
		It("should be safe for concurrent usage", func(ctx SpecContext) {
			wg := sync.WaitGroup{}
			wg.Add(2)
			go func() {
				defer wg.Done()
				Expect(IsTerminating(ctx)).To(BeFalse())
			}()
			go func() {
				defer wg.Done()
				Expect(IsTerminating(ctx)).To(BeFalse())
			}()
			wg.Wait()
		})
	})
	Describe("Shutdown()", func() {
		var spyCallback *spyCallbackHelper
		BeforeEach(func() {
			terminationErrChan = make(chan terminationError, 1)
			spyCallback = &spyCallbackHelper{}
		})
		It("should not panic if called before WithTermination()", func(ctx SpecContext) {
			cancelNotify = nil

			ctx0, cancel := context.WithCancel(ctx)
			cancel()

			Shutdown(ctx0, spyCallback.Method)

			Expect(spyCallback).To(Equal(&spyCallbackHelper{
				callsCount: 1,
				err:        errors.New("process terminated"),
				exitCode:   143,
			}))
		})
		It("should ensure termination err if terminationCtx is done", func(ctx SpecContext) {
			terminationCtx := WithTermination(ctx)
			cancelNotify()
			Shutdown(terminationCtx, spyCallback.Method)

			Expect(spyCallback).To(Equal(&spyCallbackHelper{
				callsCount: 1,
				err:        errors.New("process terminated"),
				exitCode:   143,
			}))
		})
		It("should handle panic if it happened", func(ctx SpecContext) {
			panicMsg := "my panic"

			Expect(func() {
				defer Shutdown(WithTermination(ctx), spyCallback.Method)
				panic(panicMsg)
			}).To(Not(Panic()))

			Expect(spyCallback).To(Equal(&spyCallbackHelper{
				callsCount: 1,
				err:        errors.New(panicMsg),
				exitCode:   1,
			}))
		})
		It("should do nothing if terminationCtx is not done and no panic", func(ctx SpecContext) {
			Shutdown(WithTermination(ctx), spyCallback.Method)

			Expect(spyCallback).To(Equal(&spyCallbackHelper{
				callsCount: 0,
				err:        nil,
				exitCode:   0,
			}))
		})
	})
})

type spyCallbackHelper struct {
	callsCount int
	err        error
	exitCode   int
}

func (s *spyCallbackHelper) Method(err error, exitCode int) {
	s.callsCount++
	s.err = err
	s.exitCode = exitCode
}
