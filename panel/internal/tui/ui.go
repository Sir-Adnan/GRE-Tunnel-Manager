package tui

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"
	"golang.org/x/term"
)

// ErrCancelled is returned when the operator leaves a prompt (Esc, Ctrl+C).
var ErrCancelled = errors.New("cancelled")

// ErrNoTerminal is returned by prompts when no terminal can answer them.
var ErrNoTerminal = errors.New("this step needs an answer; run it in a terminal or pass the options (see --help)")

// UI writes styled output and asks questions. Without a terminal it prints
// plain text and refuses to prompt.
type UI struct {
	in          io.Reader
	out         io.Writer // styled text, downsampled to the terminal's colors
	term        io.Writer // the terminal itself, for interactive forms
	Interactive bool
	Accessible  bool
	Width       int
	p           Palette
	theme       huh.Theme
	mu          sync.Mutex // orders output with the live progress area
	prog        progress
	file        *os.File // the terminal, for commands run between steps
}

// New attaches to the process terminal. Colors follow NO_COLOR and the
// terminal's capabilities; GTM_ACCESSIBLE=1 or TERM=dumb selects plain
// line-by-line prompts that work with screen readers.
func New(in, out *os.File) *UI {
	interactive := term.IsTerminal(int(in.Fd())) && term.IsTerminal(int(out.Fd()))
	u := build(in, colorprofile.NewWriter(out, os.Environ()), darkTerminal(os.Getenv))
	u.term, u.file = out, out
	u.Interactive = interactive
	u.Accessible = os.Getenv("GTM_ACCESSIBLE") == "1" || os.Getenv("TERM") == "dumb"
	if w, _, e := term.GetSize(int(out.Fd())); e == nil && w > 0 {
		u.Width = min(w, 76)
	}
	return u
}

// darkTerminal reads GTM_THEME (light or dark) or the COLORFGBG hint some
// terminals export, and assumes a dark background otherwise. The terminal is
// never queried: under "curl | sudo bash" the command runs on sudo's own
// pseudo-terminal, where a query can stall before anything is shown and its
// late reply is echoed on the screen.
func darkTerminal(getenv func(string) string) bool {
	switch strings.ToLower(getenv("GTM_THEME")) {
	case "light":
		return false
	case "dark":
		return true
	}
	if v := getenv("COLORFGBG"); v != "" {
		parts := strings.Split(v, ";")
		if bg, e := strconv.Atoi(parts[len(parts)-1]); e == nil {
			return bg <= 6 || bg == 8
		}
	}
	return true
}

// Plain is a colorless, non-interactive UI (tests and pipes).
func Plain(in io.Reader, out io.Writer) *UI {
	return build(in, &colorprofile.Writer{Forward: out, Profile: colorprofile.NoTTY}, true)
}

func build(in io.Reader, out io.Writer, dark bool) *UI {
	p := Signal(dark)
	return &UI{in: in, out: out, term: out, Width: 72, p: p, theme: formTheme(p)}
}

// Out is the styled writer, for commands that print free text.
func (u *UI) Out() io.Writer { return u.out }

func (u *UI) style() lipgloss.Style { return lipgloss.NewStyle() }

// line prints one line above the live progress area, if one is shown.
func (u *UI) line(s string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.clearLocked()
	fmt.Fprintln(u.out, s)
	u.drawLocked()
}

// Blank prints an empty line.
func (u *UI) Blank() { u.line("") }

// Header introduces a screen: product name, version and an optional subtitle.
func (u *UI) Header(title, version, subtitle string) {
	brand := u.style().Bold(true).Foreground(u.p.Text).Render(title)
	if version != "" {
		brand += "  " + u.style().Foreground(u.p.Muted).Render(version)
	}
	u.Blank()
	u.line("  " + brand)
	if subtitle != "" {
		u.line("  " + u.style().Foreground(u.p.Muted).Render(subtitle))
	}
	u.Rule()
}

// Rule draws a quiet divider at the content width.
func (u *UI) Rule() {
	u.line("  " + u.style().Foreground(u.p.Border).Render(strings.Repeat("─", max(u.Width-4, 20))))
}

// Section prints a small heading above a group of rows.
func (u *UI) Section(title string) {
	u.Blank()
	u.line("  " + u.style().Foreground(u.p.Accent).Bold(true).Render(title))
}

// Tone colors a status value.
type Tone int

const (
	Plainly Tone = iota
	Good
	Warning
	Bad
	Quiet
)

// Row is a label and value pair.
type Row struct {
	Label, Value string
	Tone         Tone
}

func (u *UI) toneColor(t Tone) lipgloss.Style {
	switch t {
	case Good:
		return u.style().Foreground(u.p.Success)
	case Warning:
		return u.style().Foreground(u.p.Warning)
	case Bad:
		return u.style().Foreground(u.p.Danger)
	case Quiet:
		return u.style().Foreground(u.p.Muted)
	}
	return u.style().Foreground(u.p.Text)
}

func (u *UI) renderRows(rows []Row) []string {
	width := 0
	for _, r := range rows {
		width = max(width, lipgloss.Width(r.Label))
	}
	label := u.style().Foreground(u.p.Muted).Width(width + 3)
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		value := r.Value
		if r.Tone != Plainly && r.Tone != Quiet {
			value = u.toneColor(r.Tone).Render("●") + " " + value
		} else if r.Tone == Quiet {
			value = u.toneColor(Quiet).Render(value)
		}
		out = append(out, label.Render(r.Label)+value)
	}
	return out
}

// Rows prints aligned label/value pairs; toned values get a status dot.
func (u *UI) Rows(rows []Row) {
	for _, l := range u.renderRows(rows) {
		u.line("  " + l)
	}
}

// Card frames important results, such as a new login, in a rounded box.
func (u *UI) Card(title string, rows []Row, footer ...string) {
	body := strings.Join(u.renderRows(rows), "\n")
	if len(footer) > 0 {
		notes := make([]string, len(footer))
		for i, f := range footer {
			notes[i] = u.style().Foreground(u.p.Muted).Render(f)
		}
		body += "\n\n" + strings.Join(notes, "\n")
	}
	head := u.style().Bold(true).Foreground(u.p.Accent).Render(title)
	box := u.style().Border(lipgloss.RoundedBorder()).BorderForeground(u.p.Border).Padding(0, 2).
		Render(head + "\n\n" + body)
	u.Blank()
	for _, l := range strings.Split(box, "\n") {
		u.line("  " + l)
	}
}

// Text prints a paragraph line in the body color.
func (u *UI) Text(format string, args ...any) {
	u.line("  " + u.style().Foreground(u.p.Text).Render(fmt.Sprintf(format, args...)))
}

// Hint prints secondary text.
func (u *UI) Hint(format string, args ...any) {
	u.line("  " + u.style().Foreground(u.p.Muted).Render(fmt.Sprintf(format, args...)))
}

// Command renders a copyable shell command.
func (u *UI) Command(cmd string) {
	u.line("    " + u.style().Foreground(u.p.Accent).Render(cmd))
}

// Strong highlights part of a sentence.
func (u *UI) Strong(s string) string { return u.style().Bold(true).Render(s) }

func (u *UI) mark(symbol string, c lipgloss.Style, text lipgloss.Style, format string, args []any) {
	u.line(u.markText(symbol, c, text, fmt.Sprintf(format, args...)))
}

func (u *UI) markText(symbol string, c lipgloss.Style, text lipgloss.Style, s string) string {
	return "  " + c.Render(symbol) + " " + text.Render(s)
}

func (u *UI) good() lipgloss.Style  { return u.style().Foreground(u.p.Success).Bold(true) }
func (u *UI) alert() lipgloss.Style { return u.style().Foreground(u.p.Warning).Bold(true) }
func (u *UI) bad() lipgloss.Style   { return u.style().Foreground(u.p.Danger).Bold(true) }
func (u *UI) body() lipgloss.Style  { return u.style().Foreground(u.p.Text) }

// Step announces work that is starting. On a terminal it becomes the live
// line with a spinner and the elapsed time until Done, Warn or the next Step.
func (u *UI) Step(format string, args ...any) {
	text := fmt.Sprintf(format, args...)
	if !u.animated() {
		u.line(u.markText("›", u.style().Foreground(u.p.Accent).Bold(true), u.body(), text))
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.finishLocked("✓", u.good(), "", false)
	u.startLocked(text)
}

// Done confirms finished work.
func (u *UI) Done(format string, args ...any) {
	u.finish("✓", u.good(), fmt.Sprintf(format, args...), false)
}

// Warn flags something that needs attention but did not stop the task. The
// latest output of the step that failed is shown under it.
func (u *UI) Warn(format string, args ...any) {
	u.finish("!", u.alert(), fmt.Sprintf(format, args...), true)
}

// Note prints a secondary detail under a step.
func (u *UI) Note(format string, args ...any) {
	u.mark(" ", u.style(), u.style().Foreground(u.p.Muted), format, args)
}

// Fail reports the error that ended a command.
func (u *UI) Fail(e error) {
	u.mu.Lock()
	if u.prog.task != nil {
		u.finishLocked("✗", u.bad(), "", true)
	}
	u.mu.Unlock()
	u.Blank()
	u.line(u.markText("✗", u.bad(), u.body(), capitalize(e.Error())))
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// Answer records a wizard answer as a checked line, so the choices made so
// far stay visible while the next question is asked.
func (u *UI) Answer(label, value string) {
	l := u.style().Foreground(u.p.Muted).Width(14).Render(label)
	u.line("  " + u.style().Foreground(u.p.Success).Render("✓") + " " + l + u.style().Foreground(u.p.Text).Render(value))
}
