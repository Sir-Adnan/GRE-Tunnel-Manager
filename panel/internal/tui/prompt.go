package tui

import (
	"errors"

	"charm.land/bubbles/v2/key"
	"charm.land/huh/v2"
)

// keyMap adds Esc as a way to leave any question.
func keyMap() *huh.KeyMap {
	km := huh.NewDefaultKeyMap()
	km.Quit = key.NewBinding(key.WithKeys("ctrl+c", "esc"), key.WithHelp("esc", "cancel"))
	return km
}

// Choice is one option of a selection.
type Choice[T comparable] struct {
	Label string
	Value T
}

// Run shows a form built from groups. Use it for multi-step wizards.
func (u *UI) Run(groups ...*huh.Group) error {
	if !u.Interactive && !u.Accessible {
		return ErrNoTerminal
	}
	u.Settle()
	form := huh.NewForm(groups...).
		WithTheme(u.theme).
		WithKeyMap(keyMap()).
		WithAccessible(u.Accessible).
		WithInput(u.in).
		WithOutput(u.term).
		WithWidth(u.Width - 2).
		WithShowHelp(true)
	if e := form.Run(); e != nil {
		if errors.Is(e, huh.ErrUserAborted) {
			return ErrCancelled
		}
		return e
	}
	return nil
}

// Select asks for one option. The current value is preselected.
func Select[T comparable](u *UI, title, description string, choices []Choice[T], value *T) error {
	options := make([]huh.Option[T], len(choices))
	for i, c := range choices {
		options[i] = huh.NewOption(c.Label, c.Value)
	}
	field := huh.NewSelect[T]().Title(title).Options(options...).Value(value)
	if description != "" {
		field.Description(description)
	}
	return u.Run(huh.NewGroup(field))
}

// Confirm asks a yes/no question.
func (u *UI) Confirm(title, description string, value *bool) error {
	field := huh.NewConfirm().Title(title).Affirmative("Yes").Negative("No").Value(value)
	if description != "" {
		field.Description(description)
	}
	return u.Run(huh.NewGroup(field))
}

// Input asks for one line of text, validated as it is typed.
func (u *UI) Input(title, description, placeholder string, value *string, validate func(string) error) error {
	field := huh.NewInput().Title(title).Placeholder(placeholder).Value(value)
	if description != "" {
		field.Description(description)
	}
	if validate != nil {
		field.Validate(validate)
	}
	return u.Run(huh.NewGroup(field))
}

// Secret asks for a hidden value twice and checks that both match.
func (u *UI) Secret(title string, value *string, validate func(string) error) error {
	var again string
	first := huh.NewInput().Title(title).EchoMode(huh.EchoModePassword).Value(value)
	if validate != nil {
		first.Validate(validate)
	}
	second := huh.NewInput().Title("Repeat it").EchoMode(huh.EchoModePassword).Value(&again).
		Validate(func(s string) error {
			if s != *value {
				return errors.New("the two entries differ")
			}
			return nil
		})
	return u.Run(huh.NewGroup(first, second))
}

// Hidden asks for one secret value without echoing it (API tokens).
func (u *UI) Hidden(title, description string, value *string, validate func(string) error) error {
	field := huh.NewInput().Title(title).EchoMode(huh.EchoModePassword).Value(value)
	if description != "" {
		field.Description(description)
	}
	if validate != nil {
		field.Validate(validate)
	}
	return u.Run(huh.NewGroup(field))
}
