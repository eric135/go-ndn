package util

// Optional is the base for various optional value types.
type optional struct {
	HasValue bool
}

// Unset unsets an optional value.
func (o *optional) Unset() {
	o.HasValue = false
}

// OptionalUint64 represents an optional uint64.
type OptionalUint64 struct {
	Val uint64
	optional
}

// Set sets the value of an optional uint64.
func (o *OptionalUint64) Set(val uint64) {
	o.HasValue = true
	o.Val = val
}
