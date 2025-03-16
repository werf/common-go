package cli

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/chanced/caps"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
)

var (
	FlagEnvVarsPrefix string

	definedFlagEnvVarRegexes = make(map[FlagRegexExpr]*regexp.Regexp)

	_ GetFlagEnvVarRegexesInterface = GetFlagLocalEnvVarRegexes
	_ GetFlagEnvVarRegexesInterface = GetFlagGlobalEnvVarRegexes
	_ GetFlagEnvVarRegexesInterface = GetFlagGlobalAndLocalEnvVarRegexes
	_ GetFlagEnvVarRegexesInterface = GetFlagLocalMultiEnvVarRegexes
	_ GetFlagEnvVarRegexesInterface = GetFlagGlobalMultiEnvVarRegexes
	_ GetFlagEnvVarRegexesInterface = GetFlagGlobalAndLocalMultiEnvVarRegexes
)

func NewFlagRegexExpr(expr, human string) *FlagRegexExpr {
	return &FlagRegexExpr{Expr: expr, Human: human}
}

type FlagRegexExpr struct {
	Expr  string
	Human string
}

type GetFlagEnvVarRegexesInterface func(cmd *cobra.Command, flagName string) ([]*FlagRegexExpr, error)

// Return env var regexp in the form of "^NELM_RELEASE_DEPLOY_AUTO_ROLLBACK$".
// The format is "^<prefix><command_path>_<flag_name>$".
func GetFlagLocalEnvVarRegexes(cmd *cobra.Command, flagName string) ([]*FlagRegexExpr, error) {
	commandPath := lo.Reverse(strings.SplitN(cmd.CommandPath(), " ", 2))[0]

	base := caps.ToScreamingSnake(fmt.Sprintf("%s%s_%s", FlagEnvVarsPrefix, commandPath, flagName))
	human := "$" + base
	expr := "^" + base + "$"

	return []*FlagRegexExpr{NewFlagRegexExpr(expr, human)}, nil
}

// Return env var regexp in the form of "^NELM_RELEASE_DEPLOY_LABELS_.+".
// The format is "^<prefix><command_path>_<flag_name>_.+".
func GetFlagLocalMultiEnvVarRegexes(cmd *cobra.Command, flagName string) ([]*FlagRegexExpr, error) {
	commandPath := lo.Reverse(strings.SplitN(cmd.CommandPath(), " ", 2))[0]

	base := caps.ToScreamingSnake(fmt.Sprintf("%s%s_%s", FlagEnvVarsPrefix, commandPath, flagName))
	human := "$" + base + "_*"
	expr := "^" + base + "_.+"

	return []*FlagRegexExpr{NewFlagRegexExpr(expr, human)}, nil
}

// Return env var regexp in the form of "^NELM_AUTO_ROLLBACK$".
// The format is "^<prefix><flag_name>$".
func GetFlagGlobalEnvVarRegexes(cmd *cobra.Command, flagName string) ([]*FlagRegexExpr, error) {
	base := caps.ToScreamingSnake(fmt.Sprintf("%s%s", FlagEnvVarsPrefix, flagName))
	human := "$" + base
	expr := "^" + base + "$"

	return []*FlagRegexExpr{NewFlagRegexExpr(expr, human)}, nil
}

// Return env var regexp in the form of "^NELM_LABELS_.+".
// The format is "^<prefix><flag_name>_.+".
func GetFlagGlobalMultiEnvVarRegexes(cmd *cobra.Command, flagName string) ([]*FlagRegexExpr, error) {
	base := caps.ToScreamingSnake(fmt.Sprintf("%s%s", FlagEnvVarsPrefix, flagName))
	human := "$" + base + "_*"
	expr := "^" + base + "_.+"

	return []*FlagRegexExpr{NewFlagRegexExpr(expr, human)}, nil
}

// Return env var regexps in the form of "^NELM_AUTO_ROLLBACK$" and
// "^NELM_RELEASE_DEPLOY_AUTO_ROLLBACK$". The latter has higher priority.
// The format is "^<prefix><flag_name>$" and "^<prefix><command_path>_<flag_name>$".
func GetFlagGlobalAndLocalEnvVarRegexes(cmd *cobra.Command, flagName string) ([]*FlagRegexExpr, error) {
	globalEnvVarRegexes, err := GetFlagGlobalEnvVarRegexes(cmd, flagName)
	if err != nil {
		return nil, fmt.Errorf("get global env var regexes: %w", err)
	}

	localEnvVarRegexes, err := GetFlagLocalEnvVarRegexes(cmd, flagName)
	if err != nil {
		return nil, fmt.Errorf("get local env var regexes: %w", err)
	}

	return append(globalEnvVarRegexes, localEnvVarRegexes...), nil
}

// Return env var regexps in the form of "^NELM_LABELS_.+" and "^NELM_RELEASE_DEPLOY_LABELS_.+". //
// The format is "^<prefix><flag_name>_.+" and "^<prefix><command_path>_<flag_name>_.+".
func GetFlagGlobalAndLocalMultiEnvVarRegexes(cmd *cobra.Command, flagName string) ([]*FlagRegexExpr, error) {
	globalEnvVarRegexes, err := GetFlagGlobalMultiEnvVarRegexes(cmd, flagName)
	if err != nil {
		return nil, fmt.Errorf("get global env var regexes: %w", err)
	}

	localEnvVarRegexes, err := GetFlagLocalMultiEnvVarRegexes(cmd, flagName)
	if err != nil {
		return nil, fmt.Errorf("get local env var regexes: %w", err)
	}

	return append(globalEnvVarRegexes, localEnvVarRegexes...), nil
}

func GetDefinedFlagEnvVarRegexes() map[FlagRegexExpr]*regexp.Regexp {
	return definedFlagEnvVarRegexes
}

// Get a full list of environment variables that have FlagEnvVarsPrefix as a prefix but were not defined
// with AddFlag function.
func FindUndefinedFlagEnvVarsInEnviron() []string {
	brandedEnvVars := lo.Filter(os.Environ(), func(envVar string, _ int) bool {
		return strings.HasPrefix(envVar, fmt.Sprintf("%s", FlagEnvVarsPrefix))
	})

	brandedEnvVarNames := lo.Map(brandedEnvVars, func(envVar string, _ int) string {
		envVarName, _, _ := strings.Cut(envVar, "=")
		return envVarName
	})

	var undefinedEnvVars []string
envVarsLoop:
	for _, envVar := range brandedEnvVarNames {
		for _, envVarRegex := range definedFlagEnvVarRegexes {
			if envVarRegex.MatchString(envVar) {
				continue envVarsLoop
			}
		}

		undefinedEnvVars = append(undefinedEnvVars, envVar)
	}

	return undefinedEnvVars
}
