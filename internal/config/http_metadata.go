package config

import (
	"fmt"
	"net/netip"
	"strings"
)

// parseHTTPMetadata shares strict address parsing, with a dedicated plain socket.
func parseHTTPMetadata(listen, peers string) (string, []netip.Addr, error) {
	address, trusted, err := parseHTTPProxy(listen, peers)
	if err != nil {
		return "", nil, fmt.Errorf("%s", strings.ReplaceAll(err.Error(), "HTTP PROXY", "HTTP metadata"))
	}
	if address != "" {
		parsed, _ := netip.ParseAddrPort(address)
		if parsed.Port() < 1024 {
			return "", nil, fmt.Errorf("HTTP metadata listener requires an explicit unprivileged port")
		}
	}
	return address, trusted, nil
}
