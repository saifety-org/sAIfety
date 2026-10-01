package install

import (
	"encoding/json"
	"errors"
	"os"
)

const backupSuffix = ".saifety-backup"

// readJSON loads a JSON object preserving all keys and their order-independent
// values. A missing file yields an empty object so a fresh client works.
func readJSON(path string) (map[string]json.RawMessage, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]json.RawMessage{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]json.RawMessage{}
	if len(b) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// decodeServers reads an mcpServers object; absent or null yields empty.
func decodeServers(raw json.RawMessage) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return map[string]json.RawMessage{}, nil
	}
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// writeJSON writes an object as indented JSON, atomically via a temp file.
func writeJSON(path string, obj map[string]json.RawMessage) error {
	b, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// backupOnce copies path to path+backupSuffix unless a backup already exists,
// so the very first (pre-install) state is what uninstall restores.
func backupOnce(path string) error {
	backup := path + backupSuffix
	if _, err := os.Stat(backup); err == nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return os.WriteFile(backup, data, 0o644)
}

// mergeIntoSaifety adds servers to the mcpServers object of saifety.json,
// creating the file if needed and preserving all other config fields. The
// proxy's own entry is never copied in.
func mergeIntoSaifety(path string, servers map[string]json.RawMessage) error {
	root, err := readJSON(path)
	if err != nil {
		return err
	}
	existing, err := decodeServers(root["mcpServers"])
	if err != nil {
		return err
	}
	for name, spec := range servers {
		if name == ProxyServerName {
			continue
		}
		existing[name] = spec
	}
	sb, err := json.Marshal(existing)
	if err != nil {
		return err
	}
	root["mcpServers"] = sb
	if err := os.MkdirAll(dir(path), 0o755); err != nil {
		return err
	}
	return writeJSON(path, root)
}

func dir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
