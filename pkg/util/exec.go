package util

import (
	"context"
	"os"
	"os/exec"
	"strings"
)

// ExecWerfBinaryCmd
// Deprecated: Use ExecWerfBinaryCmdContext instead.
func ExecWerfBinaryCmd(args ...string) *exec.Cmd {
	return ExecWerfBinaryCmdContext(context.Background(), args...)
}

// ExecWerfBinaryCmdContext executes werf binary in a user namespace.
func ExecWerfBinaryCmdContext(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, strings.TrimSuffix(os.Args[0], "-in-a-user-namespace"), args...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd
}

// ExecKubectlCmd
// Deprecated: Use ExecKubectlContext instead.
func ExecKubectlCmd(args ...string) *exec.Cmd {
	return ExecKubectlCmdContext(context.Background(), args...)
}

// ExecKubectlCmdContext executes werf kubectl command.
func ExecKubectlCmdContext(ctx context.Context, args ...string) *exec.Cmd {
	return ExecWerfBinaryCmdContext(ctx, append([]string{"kubectl"}, args...)...)
}
