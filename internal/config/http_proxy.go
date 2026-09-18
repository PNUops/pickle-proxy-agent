package config

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// parseHTTPProxy permits only literal, explicit peers on a dedicated socket.
func parseHTTPProxy(listen, peers string) (string, []netip.Addr, error) {
	if listen == "" && peers == "" {
		return "", nil, nil
	}
	address, err := netip.ParseAddrPort(listen)
	if err != nil || address.String() != listen || address.Port() == 0 || address.Port() == 80 ||
		address.Addr().IsUnspecified() || address.Addr().IsMulticast() || address.Addr().Is4In6() || address.Addr().Zone() != "" {
		return "", nil, fmt.Errorf("HTTP PROXY listener must be an explicit IP:port distinct from port 80")
	}
	if peers == "" {
		return "", nil, fmt.Errorf("HTTP PROXY listener requires trusted peer addresses")
	}
	var addresses []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, value := range strings.Split(peers, ",") {
		value = strings.TrimSpace(value)
		peer, err := netip.ParseAddr(value)
		if err != nil || peer.String() != value || peer.Is4In6() || peer.IsUnspecified() || peer.IsMulticast() || peer.Zone() != "" || seen[peer] {
			return "", nil, fmt.Errorf("HTTP PROXY trusted peer must be a unique literal IP: %q", value)
		}
		seen[peer] = true
		addresses = append(addresses, peer)
	}
	if len(addresses) > 16 {
		return "", nil, fmt.Errorf("HTTP PROXY listener supports at most 16 trusted peers")
	}
	slices.SortFunc(addresses, func(a, b netip.Addr) int { return a.Compare(b) })
	return listen, addresses, nil
}
