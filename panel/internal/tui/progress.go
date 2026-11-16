package tui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// Live progress for long work. Finished steps stay on screen as checked lines
// with their duration; one live area under them shows a spinner, the current
// step, the elapsed time, a bar with the step count (after Plan) and the
// latest line of command output. Command output itself is kept out of the
// way and shown only when a step fails. Without an interactive terminal the
// same calls print plain lines and command output passes straight through.

const (
	tailLines  = 15
	barWidth   = 24
	tickEvery  = 100 * time.Millisecond
	partialMax = 4096
)

var spinner = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type task struct {
	label   string
	started time.Time
	stop    chan struct{}
}

type progress struct {
	total, done int
	task        *task
	drawn       int // rows of the live area currently on screen
	frame       int
	last        string   // latest command output line
	tail        []string // recent command output, shown when a step fails
	partial     string
}

func (u *UI) animated() bool { return u.Interactive && !u.Accessible }

// Plan sets how many steps follow, for the bar. Zero hides the bar.
func (u *UI) Plan(steps int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.prog.total, u.prog.done = max(steps, 0), 0
}

// Settle ends a live step as done before something else takes the screen,
// such as a question.
func (u *UI) Settle() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.finishLocked("✓", u.good(), "", false)
}

func (u *UI) startLocked(label string) {
	t := &task{label: label, started: time.Now(), stop: make(chan struct{})}
	u.prog.task, u.prog.last, u.prog.tail, u.prog.partial = t, "", nil, ""
	u.drawLocked()
	go func() {
		tick := time.NewTicker(tickEvery)
		defer tick.Stop()
		for {
			select {
			case <-t.stop:
				return
			case <-tick.C:
				u.mu.Lock()
				if u.prog.task == t {
					u.prog.frame++
					u.clearLocked()
					u.drawLocked()
				}
				u.mu.Unlock()
			}
		}
	}()
}

func (u *UI) finish(symbol string, mark lipgloss.Style, text string, showTail bool) {
	if !u.animated() {
		u.line(u.markText(symbol, mark, u.body(), text))
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.prog.task != nil {
		u.finishLocked(symbol, mark, text, showTail)
		return
	}
	u.clearLocked()
	fmt.Fprintln(u.out, u.markText(symbol, mark, u.body(), text))
	u.prog.done++
}

// finishLocked replaces the live area with the finished step: its own label
// unless text is given, and how long it took.
func (u *UI) finishLocked(symbol string, mark lipgloss.Style, text string, showTail bool) {
	t := u.prog.task
	if t == nil {
		return
	}
	close(t.stop)
	u.clearLocked()
	u.prog.task = nil
	if text == "" {
		text = t.label
	}
	line := u.markText(symbol, mark, u.body(), text)
	if d := time.Since(t.started); d >= 300*time.Millisecond {
		line += "  " + u.style().Foreground(u.p.Muted).Render(duration(d))
	}
	fmt.Fprintln(u.out, line)
	u.prog.done++
	if showTail {
		tail := u.prog.tail
		if rest := strings.TrimSpace(u.prog.partial); rest != "" {
			tail = append(tail, clean(rest))
		}
		muted := u.style().Foreground(u.p.Muted)
		for _, l := range tail {
			fmt.Fprintln(u.out, "    "+muted.Render("│ "+ansi.Truncate(l, max(u.Width-8, 20), "…")))
		}
	}
	u.prog.last, u.prog.tail, u.prog.partial = "", nil, ""
}

// clearLocked erases the live area; the cursor returns to its first column.
func (u *UI) clearLocked() {
	if u.prog.drawn == 0 {
		return
	}
	// Back to the first row, then erase to the end of the screen, which also
	// takes anything a command printed under the area.
	_, _ = io.WriteString(u.term, "\r"+strings.Repeat("\x1b[1A", u.prog.drawn-1)+"\x1b[J")
	u.prog.drawn = 0
}

// drawLocked shows the live area without a final newline, so clearLocked
// can take it back. Every row is cut to the width so none wraps.
func (u *UI) drawLocked() {
	t := u.prog.task
	if t == nil || !u.animated() {
		return
	}
	muted := u.style().Foreground(u.p.Muted)
	rows := []string{"  " + u.style().Foreground(u.p.Accent).Bold(true).Render(spinner[u.prog.frame%len(spinner)]) + " " +
		u.body().Render(t.label) + "  " + muted.Render(clock(time.Since(t.started)))}
	if u.prog.total > 0 {
		step := min(u.prog.done+1, u.prog.total)
		filled := min(barWidth*u.prog.done/u.prog.total, barWidth)
		rows = append(rows, "    "+u.style().Foreground(u.p.Accent).Render(strings.Repeat("━", filled))+
			u.style().Foreground(u.p.Border).Render(strings.Repeat("─", barWidth-filled))+
			muted.Render(fmt.Sprintf("  %d/%d", step, u.prog.total)))
	}
	if u.prog.last != "" {
		rows = append(rows, "    "+muted.Render(u.prog.last))
	}
	width := max(u.Width-1, 30)
	for i, r := range rows {
		rows[i] = ansi.Truncate(r, width, "…")
	}
	// Autowrap is off while the area is drawn: a row the terminal measures
	// wider than we do is clipped instead of wrapped, so the row count that
	// clearLocked takes back is always right.
	_, _ = io.WriteString(u.term, "\x1b[?7l")
	_, _ = io.WriteString(u.out, strings.Join(rows, "\n"))
	_, _ = io.WriteString(u.term, "\x1b[?7h")
	u.prog.drawn = len(rows)
}

// Log is where commands run during a step write their output. On a terminal
// with a live step it keeps the output (shown when the step fails) and puts
// the latest line in the live area; otherwise it passes the output through.
func (u *UI) Log() io.Writer { return logWriter{u} }

type logWriter struct{ u *UI }

// File is the terminal itself while no step is live, so a command that talks
// to the operator (or shows its own progress) gets the real terminal.
func (w logWriter) File() *os.File {
	w.u.mu.Lock()
	defer w.u.mu.Unlock()
	if w.u.prog.task != nil {
		return nil
	}
	return w.u.file
}

func (w logWriter) Write(p []byte) (int, error) {
	u := w.u
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.prog.task == nil {
		u.clearLocked()
		return u.term.Write(p)
	}
	parts := strings.Split(u.prog.partial+string(p), "\n")
	u.prog.partial = parts[len(parts)-1]
	if len(u.prog.partial) > partialMax {
		u.prog.partial = u.prog.partial[len(u.prog.partial)-partialMax:]
	}
	for _, l := range parts[:len(parts)-1] {
		if l = clean(l); l != "" {
			u.prog.tail = append(u.prog.tail, l)
			if len(u.prog.tail) > tailLines {
				u.prog.tail = u.prog.tail[len(u.prog.tail)-tailLines:]
			}
			u.prog.last = l
		}
	}
	if l := clean(u.prog.partial); l != "" {
		u.prog.last = l
	}
	u.clearLocked()
	u.drawLocked()
	return len(p), nil
}

// clean keeps the text a terminal would finally show on one output line:
// no escape sequences, only what follows the last carriage return.
func clean(s string) string {
	s = ansi.Strip(s)
	if i := strings.LastIndexByte(strings.TrimRight(s, "\r"), '\r'); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return -1
		}
		return r
	}, s))
}

func clock(d time.Duration) string {
	s := int(d.Seconds())
	return fmt.Sprintf("%d:%02d", s/60, s%60)
}

func duration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return clock(d)
}
