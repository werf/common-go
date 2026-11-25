package cli

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"
)

var _ = Describe("AddFlag", func() {
	DescribeTable("should read a string slice flag from an environment variable",
		func(noSplitOnCommas bool, envValue string, expected []string) {
			const envVarName = "COMMON_GO_TEST_ADD_FLAG_SLICE"

			GinkgoT().Setenv(envVarName, envValue)

			var dest []string
			cmd := &cobra.Command{Use: "test"}
			Expect(AddFlag(cmd, &dest, "slice", []string{}, "Slice", AddFlagOptions{
				GetEnvVarRegexesFunc: func(cmd *cobra.Command, flagName string) ([]*FlagRegexExpr, error) {
					return []*FlagRegexExpr{NewFlagRegexExpr("^"+envVarName+"$", "$"+envVarName)}, nil
				},
				NoSplitOnCommas: noSplitOnCommas,
			})).To(Succeed())

			Expect(dest).To(Equal(expected))
		},
		Entry("split on commas by default", false, "a,b", []string{"a", "b"}),
		Entry("keep commas with NoSplitOnCommas", true, "a,b", []string{"a,b"}),
		Entry("keep escaped commas with NoSplitOnCommas", true, `name=value1\,value2`, []string{`name=value1\,value2`}),
		Entry("keep commas and quotes with NoSplitOnCommas", true, `name={"a":1,"b":2}`, []string{`name={"a":1,"b":2}`}),
	)
})
