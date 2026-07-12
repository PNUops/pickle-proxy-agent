package manager

import (
	"os"
	"path/filepath"
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
func restoreFile(path string, backup []byte, existed bool) {
	if existed {
		_ = writeFile(path, string(backup))
		return
	}
	_ = os.Remove(path)
}

// readConfDir reads all agent-managed *.conf files in dir into filename->content.
func readConfDir(dir string) (map[string][]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".conf" {
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
		if e.IsDir() || filepath.Ext(e.Name()) != ".conf" {
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
func restoreConfDir(dir string, prior map[string][]byte) {
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".conf" {
				continue
			}
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
	for name, content := range prior {
		_ = writeFile(filepath.Join(dir, name), string(content))
	}
}
