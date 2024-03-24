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
	ServerURL  string   `yaml:"serverURL"`
	Namespaces []string `yaml:"namespaces"`
	Token      string   `yaml:"token"`
}

type VulntronConfig struct {
	SaveJson bool `yaml:"save_json"`
}

type DefectDojoConfig struct {
	Url      string `yaml:"url"`
	UserName string `yaml:"username"`
	Password string `yaml:"password"`
}

type Config struct {
	Syft       SyftConfig       `yaml:"syft"`
	Grype      GrypeConfig      `yaml:"grype"`
	Loader     LoaderConfig     `yaml:"loader"`
	Vulntron   VulntronConfig   `yaml:"vulntron"`
	DefectDojo DefectDojoConfig `yaml:"defect_dojo"`
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
