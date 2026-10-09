package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Config is the agent's enrollment state: where the (pinned) control plane
// is, what name this machine was given, and the server's public key.
type Config struct {
	Server    string `json:"server"`
	Name      string `json:"name"`
	ServerKey string `json:"server_key,omitempty"` // hex ed25519 pubkey, pinned at enrollment
	// Org is the tenant this machine was enrolled under, as the control
	// plane reported it in the enrollment response. It is what secrets are
	// org-tagged against, and it is never derived from the machine name's
	// prefix: a machine enrolled before this field existed has an empty Org
	// and refuses every secrets feature with "re-enroll to learn your
	// machine's org".
	Org string `json:"org,omitempty"`
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
