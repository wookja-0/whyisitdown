package output

import (
	"os"
	"strings"
)

// palette holds the escape sequences in use. When colour is disabled every
// field is the empty string, so the renderer needs no conditionals.
type palette struct {
	reset, bold, dim         string
	green, red, yellow, cyan string
}

func newPalette(enabled bool) palette {
	if !enabled {
		return palette{}
	}
	return palette{
		reset:  "\x1b[0m",
		bold:   "\x1b[1m",
		dim:    "\x1b[2m",
		green:  "\x1b[32m",
		red:    "\x1b[31m",
		yellow: "\x1b[33m",
		cyan:   "\x1b[36m",
	}
}

func (p palette) wrap(code, s string) string {
	if code == "" {
		return s
	}
	return code + s + p.reset
}

// ColorEnabled reports whether ANSI output is appropriate for w.
//
// It honours the --no-color flag, the NO_COLOR convention and TERM=dumb, and
// otherwise requires the destination to be a terminal so that piping to a file
// or to grep stays clean.
func ColorEnabled(f *os.File, noColor bool) bool {
	if noColor {
		return false
	}
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	if strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
