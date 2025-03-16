package cli

const (
	FlagGroupIDAnnotationName       = "group-id"
	FlagGroupTitleAnnotationName    = "group-title"
	FlagGroupPriorityAnnotationName = "group-priority"
)

func NewFlagGroup(id, title string, priority int) *FlagGroup {
	return &FlagGroup{
		ID:       id,
		Title:    title,
		Priority: priority,
	}
}

type FlagGroup struct {
	// Unique group identifier.
	ID string
	// Human-readable group title, expected to be used in the usage output.
	Title string
	// FlagGroup priority, expected to be used to sort groups in the usage output.
	Priority int
}
