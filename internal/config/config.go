// config.go

package config

import (
	"os"

	"gopkg.in/yaml.v2"
)

type SyftConfig struct {
	DBRootDir           string `yaml:"db_root_dir"`
	ValidateByHashOnGet bool   `yaml:"validate_by_hash_on_get"`
}

type GrypeConfig struct {
	DBRootDir           string `yaml:"db_root_dir"`
	ListingURL          string `yaml:"listing_url"`
	ValidateByHashOnGet bool   `yaml:"validate_by_hash_on_get"`
}

type LoaderConfig struct {
	ServerURL string `yaml:"serverURL"`
	Namespace string `yaml:"namespace"`
	Token     string `yaml:"token"`
}

type VulntronConfig struct {
	SaveJson bool `yaml:"save_json"`
}

type Config struct {
	Syft     SyftConfig     `yaml:"syft"`
	Grype    GrypeConfig    `yaml:"grype"`
	Loader   LoaderConfig   `yaml:"loader"`
	Vulntron VulntronConfig `yaml:"vulntron"`
}

func ReadConfig(filename string) (Config, error) {
	var config Config

	file, err := os.Open(filename)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return Config{}, err
	}

	return config, nil
}