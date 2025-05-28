package graceful

import (
	"errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sync"
)

var _ = Describe("graceful core", func() {
	Describe("WithTermination()", func() {
		It("should return ctx with termination", func(ctx SpecContext) {
			terminationCtx := WithTermination(ctx)
			term, ok := terminationCtx.Value(terminationKey).(*termination)
			Expect(ok).To(BeTrue())
			term.cancel()
		})
	})

	Describe("Terminate()", func() {
		It("should not panic if ctx has not termination", func(ctx SpecContext) {
			Expect(func() {
				Terminate(ctx, errors.New("some err"), 1)
			}).To(PanicWith(MatchRegexp("context is not termination")))
		})
		It("should work for single usage", func(ctx SpecContext) {
			terminationCtx := WithTermination(ctx)
			err0 := errors.New("some err")
			Terminate(terminationCtx, err0, 1)
			Expect(terminationCtx.Value(terminationKey).(*termination).errChan).To(Receive(Equal(terminationError{
				err:      err0,
				exitCode: 1,
			})))
		})
		It("should do FIFO for sequential double usage", func(ctx SpecContext) {
			terminationCtx := WithTermination(ctx)
			err0 := errors.New("some err")
			err1 := errors.New("another err")
			Terminate(terminationCtx, err0, 1)
			Terminate(terminationCtx, err1, 2)
			Expect(terminationCtx.Value(terminationKey).(*termination).errChan).To(Receive(Equal(terminationError{
				err:      err0,
				exitCode: 1,
			})))
		})
		It("should be safe for concurrent usage", func(ctx SpecContext) {
			terminationCtx := WithTermination(ctx)

			err0 := errors.New("some err")
			err1 := errors.New("another err")

			wg := sync.WaitGroup{}
			wg.Add(2)
			go func() {
				defer wg.Done()
				Terminate(terminationCtx, err0, 1)
			}()
			go func() {
				defer wg.Done()
				Terminate(terminationCtx, err1, 2)
			}()
			wg.Wait()

			Expect(terminationCtx.Value(terminationKey).(*termination).errChan).To(HaveLen(1))
		})
	})
	Describe("IsTerminationContext()", func() {
		It("should return 'false' if ctx has not termination", func(ctx SpecContext) {
			Expect(IsTerminationContext(ctx)).To(BeFalse())
		})
		It("should return 'true' if ctx has termination", func(ctx SpecContext) {
			terminationCtx := WithTermination(ctx)
			terminationCtx.Value(terminationKey).(*termination).cancel()
			Expect(IsTerminationContext(terminationCtx)).To(BeTrue())
		})
	})
	Describe("IsTerminating()", func() {
		It("should return 'false' if ctx has termination", func(ctx SpecContext) {
			Expect(IsTerminating(ctx)).To(BeFalse())
		})
		It("should return 'false' if ctx has termination but it is not terminated yet", func(ctx SpecContext) {
			terminationCtx := WithTermination(ctx)
			Expect(IsTerminating(terminationCtx)).To(BeFalse())
			terminationCtx.Value(terminationKey).(*termination).cancel()
		})
		It("should return 'true' if ctx has termination and it is terminated", func(ctx SpecContext) {
			terminationCtx := WithTermination(ctx)
			terminationCtx.Value(terminationKey).(*termination).cancel()
			Expect(IsTerminating(terminationCtx)).To(BeTrue())
		})
		It("should return 'true' if ctx has termination and ctx is wrapped with another one", func(ctx SpecContext) {})
		It("should be safe for concurrent usage", func(ctx SpecContext) {
			terminationCtx := WithTermination(ctx)
			terminationCtx.Value(terminationKey).(*termination).cancel()

			wg := sync.WaitGroup{}
			wg.Add(2)
			go func() {
				defer wg.Done()
				Expect(IsTerminating(terminationCtx)).To(BeTrue())
			}()
			go func() {
				defer wg.Done()
				Expect(IsTerminating(terminationCtx)).To(BeTrue())
			}()
			wg.Wait()
		})
	})
	Describe("Shutdown()", func() {
		var spyCallback *spyCallbackHelper
		BeforeEach(func() {
			spyCallback = &spyCallbackHelper{}
		})
		It("should not panic if ctx has not termination", func(ctx SpecContext) {
			Expect(func() {
				Shutdown(ctx, spyCallback.Method)
			}).To(PanicWith(MatchRegexp("context is not termination")))

			Expect(spyCallback).To(Equal(&spyCallbackHelper{}))
		})
		It("should ensure termination err if termination is in progress", func(ctx SpecContext) {
			terminationCtx := WithTermination(ctx)
			terminationCtx.Value(terminationKey).(*termination).cancel()

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
		It("should do nothing if termination is not in progress and no panic", func(ctx SpecContext) {
			terminationCtx := WithTermination(ctx)
			Shutdown(terminationCtx, spyCallback.Method)

			Expect(spyCallback).To(Equal(&spyCallbackHelper{
				callsCount: 0,
				err:        nil,
				exitCode:   0,
			}))

			terminationCtx.Value(terminationKey).(*termination).cancel()
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
