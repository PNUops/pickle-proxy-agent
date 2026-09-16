package render

import (
	"fmt"
	"net/netip"
)

// ParseTargetNetwork validates the one IPv4 network whose guests may be
// reverse-proxy targets. A malformed value must never broaden target access.
func ParseTargetNetwork(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.String() != value {
		return netip.Prefix{}, fmt.Errorf("target network must be a canonical IPv4 network CIDR: %q", value)
	}
	return prefix, nil
}
