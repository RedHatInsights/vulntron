// config.go

package config

import (
	"os"

	"gopkg.in/yaml.v2"
)

// Configuration for the Syft tool
type SyftConfig struct {
	DBRootDir string `yaml:"db_root_dir"`
}

// Configuration for the Grype vulnerability scanner
type GrypeConfig struct {
	DBRootDir           string `yaml:"db_root_dir"`
	ListingURL          string `yaml:"listing_url"`
	ValidateByHashOnGet bool   `yaml:"validate_by_hash_on_get"`
}

// Main runtime configuration for the Vulntron application
type VulntronConfig struct {
	RunType    string `yaml:"run_type"`
	ClusterURL string `yaml:"cluster_URL"`
	Logging    struct {
		Stdout          bool   `yaml:"stdout"`
		LogFile         bool   `yaml:"log_file"`
		LogFileLocation string `yaml:"log_file_location"`
		LogFileName     string `yaml:"log_file_name"`
	} `yaml:"logging"`
}

// Configuration settings for DefectDojo integration
type DefectDojoConfig struct {
	EnableDeduplication bool `yaml:"enable_deduplication"`
	DeleteDuplicates    bool `yaml:"delete_duplicates"`
	MaxDuplicates       int  `yaml:"max_duplicates"`
	SlackNotifications  bool `yaml:"slack_notifications"`
}

// Configuration for different scan types
type ScanConfig struct {
	Name     string `yaml:"name"`
	EngName  string `yaml:"engName"`
	Function string `yaml:"function"`
	Enabled  bool   `yaml:"enabled"`
}

// Aggregate all configuration structs
type Config struct {
	Syft       SyftConfig       `yaml:"syft"`
	Grype      GrypeConfig      `yaml:"grype"`
	Vulntron   VulntronConfig   `yaml:"vulntron"`
	DefectDojo DefectDojoConfig `yaml:"defect_dojo"`
	Scan       []ScanConfig     `yaml:"scan_types"`
}

// Read and decode the YAML configuration from a file
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
