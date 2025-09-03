package graceful

import (
	"context"
	"errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sync"
	"syscall"
)

var _ = Describe("graceful core", func() {
	Describe("WithTermination()", func() {
		It("should return ctx with termination", func(ctx SpecContext) {
			terminationCtx := WithTermination(ctx)
			term, ok := terminationCtx.Value(terminationKey).(*termination)
			Expect(ok).To(BeTrue())
			term.run(TerminationDescriptor{})
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
			Expect(terminationCtx.Value(terminationKey).(*termination).descChan).To(Receive(Equal(TerminationDescriptor{
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
			Expect(terminationCtx.Value(terminationKey).(*termination).descChan).To(Receive(Equal(TerminationDescriptor{
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

			Expect(terminationCtx.Value(terminationKey).(*termination).descChan).To(HaveLen(1))
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
			terminationCtx.Value(terminationKey).(*termination).run(TerminationDescriptor{})
			Expect(IsTerminating(terminationCtx)).To(BeTrue())
		})
		It("should be safe for concurrent usage", func(ctx SpecContext) {
			terminationCtx := WithTermination(ctx)
			terminationCtx.Value(terminationKey).(*termination).run(TerminationDescriptor{})

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
		It("should panic if ctx has no termination", func(ctx SpecContext) {
			Expect(func() {
				Shutdown(ctx, spyCallback.Method)
			}).To(PanicWith(MatchRegexp("context is not termination")))

			Expect(spyCallback).To(Equal(&spyCallbackHelper{}))
		})
		It("should handle panic if it happened", func(ctx SpecContext) {
			panicMsg := "my panic"

			Expect(func() {
				defer Shutdown(WithTermination(ctx), spyCallback.Method)
				panic(panicMsg)
			}).To(Not(Panic()))

			Expect(spyCallback.CallsCount).To(Equal(1))
			Expect(spyCallback.TermDesc.Err()).To(Equal(errors.New(panicMsg)))
			Expect(spyCallback.TermDesc.ExitCode()).To(Equal(1))
			Expect(spyCallback.TermDesc.Signal()).To(BeNil())
		})
		It("should call callback if system signal received", func(ctx SpecContext) {
			terminationCtx := WithTermination(ctx)

			terminationCtx.Value(terminationKey).(*termination).run(TerminationDescriptor{
				err:      nil,
				exitCode: int(syscall.SIGINT) + 128, // SIGINT
				signal:   syscall.SIGINT,
			})

			Shutdown(terminationCtx, spyCallback.Method)

			Expect(spyCallback.CallsCount).To(Equal(1))
			Expect(spyCallback.TermDesc.Err()).To(BeNil())
			Expect(spyCallback.TermDesc.ExitCode()).To(Equal(int(syscall.SIGINT) + 128))
			Expect(spyCallback.TermDesc.Signal()).To(Equal(syscall.SIGINT))
		})
		It("should call callback even if termination is not in progress", func(ctx SpecContext) {
			terminationCtx := WithTermination(ctx)
			Shutdown(terminationCtx, spyCallback.Method)

			Expect(spyCallback.CallsCount).To(Equal(1))
			Expect(spyCallback.TermDesc.Err()).To(BeNil())
			Expect(spyCallback.TermDesc.Signal()).To(BeNil())
			Expect(spyCallback.TermDesc.ExitCode()).To(Equal(0))

			terminationCtx.Value(terminationKey).(*termination).run(TerminationDescriptor{})
		})
	})
})

type spyCallbackHelper struct {
	CallsCount int
	TermDesc   TerminationDescriptor
}

func (s *spyCallbackHelper) Method(_ context.Context, desc TerminationDescriptor) {
	s.CallsCount++
	s.TermDesc = desc
}
