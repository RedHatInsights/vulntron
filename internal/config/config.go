// config.go

package config

import (
	"os"

	"gopkg.in/yaml.v2"
)

type SyftConfig struct {
	DBRootDir string `yaml:"db_root_dir"`
}

type GrypeConfig struct {
	DBRootDir           string `yaml:"db_root_dir"`
	ListingURL          string `yaml:"listing_url"`
	ValidateByHashOnGet bool   `yaml:"validate_by_hash_on_get"`
}

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

type DefectDojoConfig struct {
	Url                 string `yaml:"url"`
	UserName            string `yaml:"username"`
	Password            string `yaml:"password"`
	EnableDeduplication bool   `yaml:"enable_deduplication"`
	DeleteDuplicates    bool   `yaml:"delete_duplicates"`
	MaxDuplicates       int    `yaml:"max_duplicates"`
}

type ScanConfig struct {
	Name     string `yaml:"name"`
	EngName  string `yaml:"engName"`
	Function string `yaml:"function"`
	Enabled  bool   `yaml:"enabled"`
}

type Config struct {
	Syft       SyftConfig       `yaml:"syft"`
	Grype      GrypeConfig      `yaml:"grype"`
	Vulntron   VulntronConfig   `yaml:"vulntron"`
	DefectDojo DefectDojoConfig `yaml:"defect_dojo"`
	Scan       []ScanConfig     `yaml:"scan_types"`
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
