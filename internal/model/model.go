// Package model holds the wire types exchanged with pickle-api over the
// internal reverse-proxy control link (docs/api/internal.md, Link 2). Field names
// and JSON shapes here are the frozen contract that pickle-api's client mirrors.
package model

import "time"

// DesiredState is the presence of a vhost for one FQDN.
type DesiredState string

const (
	// Present renders/replaces the vhost.
	Present DesiredState = "PRESENT"
	// Absent removes the vhost file (unpublish / VM deletion).
	Absent DesiredState = "ABSENT"
)

// CertRefWildcard selects the platform Cloudflare Origin CA wildcard certificate.
// Any other certRef is treated as a per-domain Let's Encrypt certificate.
const CertRefWildcard = "origin-wildcard"

// Route is the full desired state for one FQDN. It is the POST /apply body and
// also each entry in a /sync-all manifest.
type Route struct {
	FQDN         string       `json:"fqdn"`
	DesiredState DesiredState `json:"desiredState"`
	Generation   int64        `json:"generation"`
	TargetIP     string       `json:"targetIp,omitempty"`
	TargetPort   int          `json:"targetPort,omitempty"`
	CertRef      string       `json:"certRef,omitempty"`
}

// ApplyResult is the POST /apply response body. On 200 Applied is true and
// Generation echoes the applied generation. On 409 (stale) Applied is false and
// Generation carries the currently applied generation. On 422 Applied is false
// and Error carries the nginx stderr.
type ApplyResult struct {
	Applied    bool   `json:"applied"`
	Generation int64  `json:"generation"`
	Error      string `json:"error,omitempty"`
}

// SyncAllRequest is the POST /sync-all body: the authoritative full snapshot.
type SyncAllRequest struct {
	SnapshotGeneration int64   `json:"snapshotGeneration"`
	Routes             []Route `json:"routes"`
}

// FQDNResult is one per-FQDN outcome inside a SyncAllResult.
type FQDNResult struct {
	FQDN       string `json:"fqdn"`
	Applied    bool   `json:"applied"`
	Generation int64  `json:"generation"`
	Error      string `json:"error,omitempty"`
}

// SyncAllResult is the POST /sync-all response body.
type SyncAllResult struct {
	Applied            bool         `json:"applied"`
	SnapshotGeneration int64        `json:"snapshotGeneration"`
	Pruned             []string     `json:"pruned,omitempty"`
	Results            []FQDNResult `json:"results"`
	Error              string       `json:"error,omitempty"`
}

// CertState is the issuance/renewal state for a custom domain's certificate.
type CertState string

const (
	CertOK      CertState = "OK"
	CertPending CertState = "PENDING"
	CertFailed  CertState = "FAILED"
)

// RouteStatus is one FQDN's applied state, reported by GET /status.
type RouteStatus struct {
	FQDN       string    `json:"fqdn"`
	Present    bool      `json:"present"`
	Generation int64     `json:"generation"`
	AppliedAt  time.Time `json:"appliedAt"`
}

// CertStatus is one custom domain's certificate state, reported by GET /status.
type CertStatus struct {
	FQDN      string    `json:"fqdn"`
	State     CertState `json:"state"`
	CheckedAt time.Time `json:"checkedAt"`
	Error     string    `json:"error,omitempty"`
}

// Event records the outcome of the most recent apply or sync.
type Event struct {
	At     time.Time `json:"at"`
	OK     bool      `json:"ok"`
	Detail string    `json:"detail,omitempty"`
	Error  string    `json:"error,omitempty"`
}

// StatusResponse is the GET /status body.
type StatusResponse struct {
	Health    string        `json:"health"`
	StartedAt time.Time     `json:"startedAt"`
	Now       time.Time     `json:"now"`
	LastApply *Event        `json:"lastApply,omitempty"`
	LastSync  *Event        `json:"lastSync,omitempty"`
	Routes    []RouteStatus `json:"routes"`
	Certs     []CertStatus  `json:"certs"`
}

// Problem is the problem+json body used for chain-level rejections (auth/source/
// rate limit), mirroring the pickle-api /internal error shape.
type Problem struct {
	Code string `json:"code"`
}
