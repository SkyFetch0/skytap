package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type persisted struct {
	States    map[string]DomainState `json:"states"`
	PinBypass bool                   `json:"pin_bypass,omitempty"`
}

func persistExists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "state.json"))
	return err == nil
}

func loadPersist(dir string, reg *Registry, rules *RuleEngine) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	sf := filepath.Join(dir, "state.json")
	if b, err := os.ReadFile(sf); err == nil {
		var p persisted
		if json.Unmarshal(b, &p) == nil {
			if p.States != nil {
				reg.loadStates(p.States)
			}
		}
	}
	rf := filepath.Join(dir, "rules.json")
	if b, err := os.ReadFile(rf); err == nil {
		var rs []Rule
		if json.Unmarshal(b, &rs) == nil {
			rules.Set(rs)
		}
	}
	return nil
}

func savePersist(dir string, reg *Registry, rules *RuleEngine) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	p := persisted{States: reg.snapshot()}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), b, 0o644); err != nil {
		return err
	}
	rb, err := json.MarshalIndent(rules.All(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "rules.json"), rb, 0o644)
}
