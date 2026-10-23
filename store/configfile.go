package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/lsongdev/dns-go/config"
)

// dataKeys are the top-level config keys that hold config.Data.
var dataKeys = []string{"domains", "filters", "access"}

// ConfigFile stores config.Data in the YAML config file. Updates rewrite
// only the data sections; every other key keeps its formatting and
// comments.
type ConfigFile struct {
	path string
	mu   sync.Mutex
}

func NewConfigFile(path string) *ConfigFile { return &ConfigFile{path: path} }

func (s *ConfigFile) Load(ctx context.Context) (config.Data, error) {
	cfg, err := config.Load(s.path)
	if err != nil {
		return config.Data{}, err
	}
	return cfg.Data, nil
}

func (s *ConfigFile) Update(ctx context.Context, fn func(*config.Data) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		return err
	}
	data := cfg.Data.Clone()
	if err := fn(&data); err != nil {
		return err
	}
	out, err := replaceDataSections(raw, data)
	if err != nil {
		return err
	}
	return writeAtomic(s.path, out)
}

func (s *ConfigFile) Close() error { return nil }

// replaceDataSections swaps the data keys of the YAML document in raw for
// those of data, appending keys that were absent and dropping empty ones.
func replaceDataSections(raw []byte, data config.Data) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("store: config file is not a YAML mapping")
	}
	var encoded yaml.Node
	if err := encoded.Encode(data); err != nil {
		return nil, err
	}
	sections := map[string]*yaml.Node{}
	for i := 0; i+1 < len(encoded.Content); i += 2 {
		sections[encoded.Content[i].Value] = encoded.Content[i+1]
	}

	root := doc.Content[0]
	seen := map[string]bool{}
	kept := root.Content[:0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		if isDataKey(key.Value) {
			seen[key.Value] = true
			replacement, ok := sections[key.Value]
			if !ok {
				continue // section is now empty: drop the key
			}
			value = replacement
		}
		kept = append(kept, key, value)
	}
	root.Content = kept
	for _, k := range dataKeys {
		if v, ok := sections[k]; ok && !seen[k] {
			root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, v)
		}
	}
	return yaml.Marshal(&doc)
}

func isDataKey(k string) bool {
	for _, d := range dataKeys {
		if d == k {
			return true
		}
	}
	return false
}

// writeAtomic replaces path with data, keeping the file's permissions.
func writeAtomic(path string, data []byte) error {
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
