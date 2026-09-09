package reporting

import (
	"encoding/json"
	"io"
)

// WriteJSON renders the report as deterministic, stable JSON for agents
// and scripts. Key order follows struct definition; no decorative text is
// ever written to the stream.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
