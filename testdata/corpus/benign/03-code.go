package widget

// Assemble builds a widget from parts and returns an error if a part is missing.
func Assemble(parts []Part) (*Widget, error) {
	if len(parts) == 0 {
		return nil, ErrNoParts
	}
	return &Widget{parts: parts}, nil
}
