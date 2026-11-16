// Package tui renders gtm's terminal interface: a calm status layout, step
// progress and themed forms. It knows nothing about installation; callers
// pass text and choices in.
package tui

import (
	"image/color"

	"charm.land/bubbles/v2/help"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
)

// Palette follows the panel's Signal preset. Body text keeps the terminal's
// own foreground; every accent meets WCAG AA on the matching background.
type Palette struct {
	Text, Muted, Subtle, Border     color.Color
	Accent, OnAccent, Surface       color.Color
	Success, Warning, Danger, Focus color.Color
}

// Signal returns the palette for a dark or light terminal background.
func Signal(dark bool) Palette {
	if dark {
		return Palette{
			Text: lipgloss.NoColor{}, Muted: lipgloss.Color("#9a9cab"), Subtle: lipgloss.Color("#6e7180"), Border: lipgloss.Color("#3a3d46"),
			Accent: lipgloss.Color("#5794f2"), OnAccent: lipgloss.Color("#0b0d12"), Surface: lipgloss.Color("#1d2a44"),
			Success: lipgloss.Color("#73bf69"), Warning: lipgloss.Color("#ff9830"), Danger: lipgloss.Color("#f05b8e"), Focus: lipgloss.Color("#8ab4ff"),
		}
	}
	return Palette{
		Text: lipgloss.NoColor{}, Muted: lipgloss.Color("#565c66"), Subtle: lipgloss.Color("#7c828c"), Border: lipgloss.Color("#d5d9e0"),
		Accent: lipgloss.Color("#3d71d9"), OnAccent: lipgloss.Color("#ffffff"), Surface: lipgloss.Color("#e5edfc"),
		Success: lipgloss.Color("#187a46"), Warning: lipgloss.Color("#9a5800"), Danger: lipgloss.Color("#cf1157"), Focus: lipgloss.Color("#2456b8"),
	}
}

// formTheme maps the palette onto huh forms.
func formTheme(p Palette) huh.Theme {
	return huh.ThemeFunc(func(isDark bool) *huh.Styles {
		t := huh.ThemeBase(isDark)
		// Forms line up with the two-space indent of every other line.
		t.Form.Base = lipgloss.NewStyle().MarginLeft(2)
		text := lipgloss.NewStyle().Foreground(p.Text)
		muted := lipgloss.NewStyle().Foreground(p.Muted)

		t.Focused.Base = t.Focused.Base.BorderForeground(p.Accent)
		t.Focused.Card = t.Focused.Base
		t.Focused.Title = text.Bold(true)
		t.Focused.NoteTitle = text.Bold(true).MarginBottom(1)
		t.Focused.Description = muted
		t.Focused.ErrorIndicator = t.Focused.ErrorIndicator.Foreground(p.Danger)
		t.Focused.ErrorMessage = t.Focused.ErrorMessage.Foreground(p.Danger)
		t.Focused.SelectSelector = lipgloss.NewStyle().Foreground(p.Accent).Bold(true).SetString("› ")
		t.Focused.NextIndicator = t.Focused.NextIndicator.Foreground(p.Accent)
		t.Focused.PrevIndicator = t.Focused.PrevIndicator.Foreground(p.Accent)
		t.Focused.Option = text
		t.Focused.MultiSelectSelector = t.Focused.SelectSelector
		t.Focused.SelectedOption = lipgloss.NewStyle().Foreground(p.Accent).Bold(true)
		t.Focused.SelectedPrefix = lipgloss.NewStyle().Foreground(p.Success).SetString("✓ ")
		t.Focused.UnselectedOption = text
		t.Focused.UnselectedPrefix = muted.SetString("· ")
		t.Focused.FocusedButton = t.Focused.FocusedButton.Foreground(p.OnAccent).Background(p.Accent).Bold(true)
		t.Focused.BlurredButton = t.Focused.BlurredButton.Foreground(p.Muted).Background(p.Surface)
		t.Focused.TextInput.Cursor = lipgloss.NewStyle().Foreground(p.Focus)
		t.Focused.TextInput.Placeholder = lipgloss.NewStyle().Foreground(p.Subtle)
		t.Focused.TextInput.Prompt = lipgloss.NewStyle().Foreground(p.Accent)
		t.Focused.TextInput.Text = text

		t.Blurred = t.Focused
		t.Blurred.Base = t.Focused.Base.BorderStyle(lipgloss.HiddenBorder())
		t.Blurred.Card = t.Blurred.Base
		t.Blurred.Title = muted.Bold(true)
		t.Blurred.SelectSelector = lipgloss.NewStyle().SetString("  ")
		t.Blurred.MultiSelectSelector = lipgloss.NewStyle().SetString("  ")
		t.Blurred.NextIndicator = lipgloss.NewStyle()
		t.Blurred.PrevIndicator = lipgloss.NewStyle()

		t.Group.Title = t.Focused.Title
		t.Group.Description = t.Focused.Description

		keys := lipgloss.NewStyle().Foreground(p.Muted)
		desc := lipgloss.NewStyle().Foreground(p.Subtle)
		t.Help = help.Styles{
			ShortKey: keys, ShortDesc: desc, ShortSeparator: desc, Ellipsis: desc,
			FullKey: keys, FullDesc: desc, FullSeparator: desc,
		}
		return t
	})
}
