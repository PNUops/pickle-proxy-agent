package nginx

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// ReloadProofConfig is reserved for the agent's private configuration receipt.
// Its underscore prevents collision with a valid domain name.
const ReloadProofConfig = "_pickle_reload_proof.conf"

const proofHeader = "# Managed reload proof for pickle-proxy-agent\n"

// NewVerified requires a fresh private response from the reloaded configuration.
// The include directory must be part of nginx's http context.
func NewVerified(bin string, timeout time.Duration, dir string) (*Exec, error) {
	dir = filepath.Clean(dir)
	if !filepath.IsAbs(dir) || !regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`).MatchString(dir) {
		return nil, fmt.Errorf("nginx proof directory must be an absolute path without config metacharacters")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || int(owner.Uid) != os.Geteuid() || info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("nginx proof directory must be owned by the agent and not writable by group or others")
	}
	socket := filepath.Join(dir, "_pickle_reload_proof.sock")
	if len(socket) > 103 {
		return nil, fmt.Errorf("nginx proof socket path exceeds the portable Unix socket limit")
	}
	e := New(bin, timeout)
	e.proofDir, e.proofSocket = dir, socket
	e.ProofTimeout = min(10*time.Second, e.Timeout)
	if err := e.checkProofOwner(); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Exec) checkProofOwner() error {
	path := filepath.Join(e.proofDir, ReloadProofConfig)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("reserved nginx proof path is not a regular file")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(contents), proofHeader) {
		return fmt.Errorf("reserved nginx proof file is not agent-owned")
	}
	return nil
}

func (e *Exec) prepareProof() error {
	e.proofExpected, e.proofURI = "", ""
	if err := e.checkProofOwner(); err != nil {
		return err
	}
	entries, err := os.ReadDir(e.proofDir)
	if err != nil {
		return err
	}
	hash := sha256.New()
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".conf" || entry.Name() == ReloadProofConfig {
			continue
		}
		data, err := os.ReadFile(filepath.Join(e.proofDir, entry.Name()))
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(hash, "%s\x00%d\x00", entry.Name(), len(data))
		_, _ = hash.Write(data)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	uri := "/_reload/" + hex.EncodeToString(nonce)
	expected := hex.EncodeToString(nonce) + ":" + hex.EncodeToString(hash.Sum(nil))
	config := fmt.Sprintf("%sserver {\n    listen unix:%s;\n    server_name _;\n    access_log off;\n    location = %s { return 200 \"%s\"; }\n    location / { return 404; }\n}\n", proofHeader, e.proofSocket, uri, expected)
	file, err := os.CreateTemp(e.proofDir, ".reload-proof-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0640); err == nil {
		_, err = file.WriteString(config)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(file.Name(), filepath.Join(e.proofDir, ReloadProofConfig)); err != nil {
		return err
	}
	e.proofURI, e.proofExpected = uri, expected
	return nil
}

func (e *Exec) waitForProof(ctx context.Context) error {
	wait := e.ProofTimeout
	if wait <= 0 {
		wait = min(10*time.Second, e.Timeout)
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	transport := &http.Transport{DisableKeepAlives: true, DisableCompression: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", e.proofSocket)
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://reload.invalid"+e.proofURI, nil)
		if err != nil {
			return err
		}
		response, err := client.Do(req)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 512))
			response.Body.Close()
			if response.StatusCode == http.StatusOK && readErr == nil && string(body) == e.proofExpected {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("nginx reload did not confirm the new local configuration proof: %w", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}
