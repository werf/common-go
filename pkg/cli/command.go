package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

const CommandPriorityAnnotationName = "command-priority"

func NewRootCommand(ctx context.Context, use, long string) *cobra.Command {
	cmd := &cobra.Command{
		Use:           use,
		Long:          long,
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.PersistentFlags().BoolP("help", "h", false, "Show help")
	cmd.PersistentFlags().Lookup("help").Hidden = true

	return cmd
}

type GroupCommandOptions struct{}

func NewGroupCommand(ctx context.Context, use, short, long string, group *CommandGroup, options GroupCommandOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   use,
		Short:                 short,
		Long:                  long,
		Args:                  cobra.NoArgs,
		ValidArgsFunction:     cobra.NoFileCompletions,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			CommandGroupIDAnnotationName:       group.ID,
			CommandGroupTitleAnnotationName:    group.Title,
			CommandGroupPriorityAnnotationName: fmt.Sprintf("%d", group.Priority),
		},
	}

	return cmd
}

type SubCommandOptions struct {
	Args              cobra.PositionalArgs
	ValidArgsFunction func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective)
}

func NewSubCommand(ctx context.Context, use, short, long string, priority int, group *CommandGroup, options SubCommandOptions, runE func(cmd *cobra.Command, args []string) error) *cobra.Command {
	if options.Args == nil {
		options.Args = cobra.NoArgs
	}

	if options.ValidArgsFunction == nil {
		options.ValidArgsFunction = cobra.NoFileCompletions
	}

	cmd := &cobra.Command{
		Use:                   use,
		Short:                 short,
		Long:                  long,
		Args:                  options.Args,
		ValidArgsFunction:     options.ValidArgsFunction,
		DisableFlagsInUseLine: true,
		RunE:                  runE,
	}

	SetSubCommandAnnotations(cmd, priority, group)

	return cmd
}

func SetSubCommandAnnotations(cmd *cobra.Command, priority int, group *CommandGroup) {
	cmd.Annotations = map[string]string{
		CommandGroupIDAnnotationName:       group.ID,
		CommandGroupTitleAnnotationName:    group.Title,
		CommandGroupPriorityAnnotationName: fmt.Sprintf("%d", group.Priority),
		CommandPriorityAnnotationName:      fmt.Sprintf("%d", priority),
	}
}
