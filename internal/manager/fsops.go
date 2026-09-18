package manager

import (
	"os"
	"path/filepath"

	"github.com/pnuops/pickle-proxy-agent/internal/nginx"
)

// filePerm is the mode for rendered vhost files (root-owned, group-readable by nginx).
const filePerm = 0o640

// readFileMaybe returns the file content and whether it existed. A missing file is
// not an error (it is the normal case for a first apply or an ABSENT on a fresh FQDN).
func readFileMaybe(path string) (content []byte, existed bool, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return b, true, nil
}

// writeFile writes content atomically (temp + rename) so a reader never sees a
// half-written vhost.
func writeFile(path, content string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), filePerm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// restoreFile puts a file back to its pre-mutation state: rewrite the backed-up
// content if it existed, otherwise remove whatever we wrote.
func restoreFile(path string, backup []byte, existed bool) error {
	if existed {
		return writeFile(path, string(backup))
	}
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func isRouteConfig(entry os.DirEntry) bool {
	return !entry.IsDir() && filepath.Ext(entry.Name()) == ".conf" && entry.Name() != nginx.ReloadProofConfig
}

// readConfDir reads all agent-managed *.conf files in dir into filename->content.
func readConfDir(dir string) (map[string][]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, e := range entries {
		if !isRouteConfig(e) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out[e.Name()] = b
	}
	return out, nil
}

// writeConfDir makes the on-disk agent-managed set exactly `desired`: write every
// desired file, remove every other *.conf. Used by /sync-all's authoritative swap.
func writeConfDir(dir string, desired map[string]string) error {
	for name, content := range desired {
		if err := writeFile(filepath.Join(dir, name), content); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !isRouteConfig(e) {
			continue
		}
		if _, keep := desired[e.Name()]; !keep {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}

// restoreConfDir returns the agent-managed set to exactly `prior`: remove every
// current *.conf, then rewrite the backup. Called after a failed swap so the live
// tree is left untouched.
func restoreConfDir(dir string, prior map[string][]byte) error {
	desired := make(map[string]string, len(prior))
	for name, content := range prior {
		desired[name] = string(content)
	}
	return writeConfDir(dir, desired)
}
