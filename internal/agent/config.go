package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Config is the agent's enrollment state: where the control plane is and
// what name this machine was given.
type Config struct {
	Server string `json:"server"`
	Name   string `json:"name"`
}

func configPath(stateDir string) string { return filepath.Join(stateDir, "config.json") }

func LoadConfig(stateDir string) (*Config, error) {
	raw, err := os.ReadFile(configPath(stateDir))
	if err != nil {
		return nil, errors.New("not enrolled yet: run `mach register` first (config.json missing in " + stateDir + ")")
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	if c.Server == "" || c.Name == "" {
		return nil, errors.New("corrupt config.json — delete it and re-enroll")
	}
	return &c, nil
}

func SaveConfig(stateDir string, c *Config) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath(stateDir), raw, 0o600)
}