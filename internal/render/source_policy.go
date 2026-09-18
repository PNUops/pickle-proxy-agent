package render

import (
	"strings"

	"github.com/pnuops/pickle-proxy-agent/internal/sourcepolicy"
)

// sourcePolicyDirectives belongs only inside the proxied location. Keeping it
// out of the server block leaves HTTP-01 challenges independent of site access.
// nginx evaluates these directives against its restored remote address, never
// against a caller-controlled HTTP header.
func sourcePolicyDirectives(policy *sourcepolicy.Policy) string {
	if policy == nil {
		return ""
	}
	var out strings.Builder
	for _, prefix := range policy.Prefixes() {
		out.WriteString("        allow ")
		out.WriteString(prefix.String())
		out.WriteString(";\n")
	}
	out.WriteString("        deny all;\n")
	return out.String()
}
