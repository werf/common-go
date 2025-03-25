package chart_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestChart(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Chart Suite")
}
