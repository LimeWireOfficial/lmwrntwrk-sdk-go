//go:build go1.16

package allowlist

import _ "embed"

//go:embed actions.json
var actionsJSON []byte
