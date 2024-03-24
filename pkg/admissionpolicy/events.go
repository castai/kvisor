package admissionpolicy

// ValidationEvent represents an event produced from a failed validation.
type ValidationEvent struct {
	// Policy is the name of the policy that failed.
	Policy string
	// Binding is the name of the binding that failed.
	Binding string
	// ObjectKind is the kind of the object that failed.
	ObjectKind string
	// ObjectName is the name of the object that failed.
	ObjectName string
	// ObjectNamespace is the namespace of the object that failed.
	ObjectNamespace string
}
