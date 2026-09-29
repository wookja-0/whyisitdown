package output

import (
	"encoding/json"
	"io"

	"github.com/wookja-0/whyisitdown/internal/check"
)

// JSON writes the machine-readable report: no colour, no decoration, and a
// trailing newline so it composes with line-oriented tools.
func JSON(w io.Writer, r check.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
