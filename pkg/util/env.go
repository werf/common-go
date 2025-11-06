package util

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/samber/lo"
)

func LookupBoolEnvironment(environmentName string) (*bool, bool) {
	value, isSet := os.LookupEnv(environmentName)
	if !isSet {
		return nil, false
	}

	switch value {
	case "1", "true", "yes":
		t := true
		return &t, true
	case "0", "false", "no":
		f := false
		return &f, true
	}
	return nil, true
}

func GetBoolEnvironment(environmentName string) *bool {
	val, _ := LookupBoolEnvironment(environmentName)
	return val
}

func GetBoolEnvironmentDefaultFalse(environmentName string) bool {
	switch os.Getenv(environmentName) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

func GetBoolEnvironmentDefaultTrue(environmentName string) bool {
	switch os.Getenv(environmentName) {
	case "0", "false", "no":
		return false
	default:
		return true
	}
}

func GetFirstExistingEnvVarAsString(envNames ...string) string {
	for _, envName := range envNames {
		if v := os.Getenv(envName); v != "" {
			return v
		}
	}

	return ""
}

func GetFirstExistingEnvVarAsInt(envNames ...string) (*int, error) {
	for _, envName := range envNames {
		result, err := GetIntEnvVar(envName)
		if err != nil {
			return nil, err
		}

		if result != nil {
			return lo.ToPtr(int(*result)), nil
		}
	}

	return nil, nil
}

func PredefinedValuesByEnvNamePrefix(envNamePrefix string, envNamePrefixesToExcept ...string) []string {
	var result []string

	env := os.Environ()
	sort.Strings(env)

environLoop:
	for _, keyValue := range env {
		parts := strings.SplitN(keyValue, "=", 2)
		if strings.HasPrefix(parts[0], envNamePrefix) {
			for _, exceptEnvNamePrefix := range envNamePrefixesToExcept {
				if strings.HasPrefix(parts[0], exceptEnvNamePrefix) {
					continue environLoop
				}
			}

			result = append(result, parts[1])
		}
	}

	return result
}

func GetInt64EnvVar(varName string) (*int64, error) {
	if v := os.Getenv(varName); v != "" {
		vInt, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad %s variable value %q: %w", varName, v, err)
		}

		res := new(int64)
		*res = vInt

		return res, nil
	}

	return nil, nil
}

func GetIntEnvVar(varName string) (*int64, error) {
	if v := os.Getenv(varName); v != "" {
		vInt, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad %s variable value %q: %w", varName, v, err)
		}

		res := new(int64)
		*res = vInt

		return res, nil
	}

	return nil, nil
}

func GetIntEnvVarDefault(varName string, defaultValue int) (int, error) {
	val, err := GetIntEnvVar(varName)
	if err != nil {
		return 0, err
	}

	if val == nil {
		return defaultValue, nil
	}

	return int(*val), nil
}

func GetUint64EnvVar(varName string) (*uint64, error) {
	if v := os.Getenv(varName); v != "" {
		vUint, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad %s variable value %q: %w", varName, v, err)
		}

		res := new(uint64)
		*res = vUint

		return res, nil
	}

	return nil, nil
}

func GetIntEnvVarStrict(varName string) *int64 {
	valP, err := GetIntEnvVar(varName)
	if err != nil {
		panic(fmt.Sprintf("bad %s value: %s", varName, err))
	}
	return valP
}

func GetUint64EnvVarStrict(varName string) *uint64 {
	valP, err := GetUint64EnvVar(varName)
	if err != nil {
		panic(fmt.Sprintf("bad %s value: %s", varName, err))
	}
	return valP
}

func GetStringToStringEnvVar(varName string) (map[string]string, error) {
	result := map[string]string{}

	val := os.Getenv(varName)
	if val == "" {
		return result, nil
	}

	var ss []string
	n := strings.Count(val, "=")
	switch n {
	case 0:
		return nil, fmt.Errorf("%s must be formatted as key=value", val)
	case 1:
		ss = append(ss, strings.Trim(val, `"`))
	default:
		r := csv.NewReader(strings.NewReader(val))
		var err error
		ss, err = r.Read()
		if err != nil {
			return nil, err
		}
	}

	for _, pair := range ss {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("%s must be formatted as key=value", pair)
		}
		result[kv[0]] = kv[1]
	}

	return result, nil
}

func GetDurationEnvVar(varName string) (time.Duration, error) {
	if v := os.Getenv(varName); v != "" {
		vDuration, err := time.ParseDuration(v)
		if err != nil {
			return 0, fmt.Errorf("bad %s variable value %q: %w", varName, v, err)
		}

		return vDuration, nil
	}

	return 0, nil
}
