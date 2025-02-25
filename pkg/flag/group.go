package flag

const (
	GroupIDAnnotationName       = "group-id"
	GroupTitleAnnotationName    = "group-title"
	GroupPriorityAnnotationName = "group-priority"
)

func NewGroup(id, title string, priority int) *Group {
	return &Group{
		ID:       id,
		Title:    title,
		Priority: priority,
	}
}

type Group struct {
	// Unique group identifier.
	ID string
	// Human-readable group title, expected to be used in the usage output.
	Title string
	// Group priority, expected to be used to sort groups in the usage output.
	Priority int
}
