package graceful

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestGraceful(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "graceful suite")
}
