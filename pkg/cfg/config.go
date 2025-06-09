package cfg

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/yamlpatch"
)

type BouncerConfig struct {
	Interface      string        `yaml:"interface"`
	MetricsEnabled bool          `yaml:"metrics"`
	Logging        LoggingConfig `yaml:",inline"`
}

// MergedConfig() returns the byte content of the patched configuration file (with .yaml.local).
func MergedConfig(configPath string) ([]byte, error) {
	patcher := yamlpatch.NewPatcher(configPath, ".local")

	data, err := patcher.MergedPatchContent()
	if err != nil {
		return nil, err
	}

	return data, nil
}

func NewConfig(reader io.Reader) (*BouncerConfig, error) {
	config := &BouncerConfig{}
	fcontent, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(fcontent, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}

	if err = config.Logging.setup("crowdsec-ebpf-bouncer.log"); err != nil {
		return nil, fmt.Errorf("failed to setup logging: %w", err)
	}

	return config, nil
}
