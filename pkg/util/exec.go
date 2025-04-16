package util

import (
	"context"
	"os"
	"os/exec"
	"strings"
)

// ExecWerfBinaryCmdContext executes werf binary in a user namespace.
func ExecWerfBinaryCmdContext(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, strings.TrimSuffix(os.Args[0], "-in-a-user-namespace"), args...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd
}

// ExecKubectlCmdContext executes werf kubectl command.
func ExecKubectlCmdContext(ctx context.Context, args ...string) *exec.Cmd {
	return ExecWerfBinaryCmdContext(ctx, append([]string{"kubectl"}, args...)...)
}
