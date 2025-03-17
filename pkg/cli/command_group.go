package cli

const (
	CommandGroupIDAnnotationName       = "group-id"
	CommandGroupTitleAnnotationName    = "group-title"
	CommandGroupPriorityAnnotationName = "group-priority"
)

func NewCommandGroup(id, title string, priority int) *CommandGroup {
	return &CommandGroup{
		ID:       id,
		Title:    title,
		Priority: priority,
	}
}

type CommandGroup struct {
	// Unique group identifier.
	ID string
	// Human-readable group title, expected to be used in the usage output.
	Title string
	// CommandGroup priority, expected to be used to sort groups in the usage output.
	Priority int
}
