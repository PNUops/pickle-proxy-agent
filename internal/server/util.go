package server

import (
	"net"
	"time"
)

const (
	// maxBodyBytes caps request bodies — control payloads are tiny.
	maxBodyBytes = 1 << 20 // 1 MiB
	// shutdownGrace bounds in-flight request draining on shutdown.
	shutdownGrace = 10 * time.Second
)

// sourceKey extracts the host portion of a RemoteAddr for rate-limit keying.
func sourceKey(remoteAddr string) string {
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return h
	}
	return remoteAddr
}
