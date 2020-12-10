package util

// Optional represents a variable with an optional value.
type Optional struct {
	Value    interface{}
	HasValue bool
}

// Unset unsets an optional value.
func (o *Optional) Unset() {
	o.HasValue = false
}

// Set sets an optional value.
func (o *Optional) Set(val interface{}) {
	o.Value = val
	o.HasValue = true
}
