package vulntron_syft

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/RedHatInsights/Vulntron/internal/config"
	"github.com/RedHatInsights/Vulntron/internal/utils"
	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func RunSyft(config config.VulntronConfig, message string) (string, error) {
	log.Printf("Running syft for message: %s", message)
	imageTag := string(message)

	scope, err := source.Detect(imageTag, source.DefaultDetectConfig())
	if err != nil {
		return "", fmt.Errorf("failed to detect source: %w", err)
	}
	log.Printf("Detected source: %v", scope)

	src, err := scope.NewSource(source.DefaultDetectionSourceConfig())
	if err != nil {
		return "", fmt.Errorf("failed to create source: %w", err)
	}

	result := sbom.SBOM{
		Source: src.Describe(),
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "0.96.0",
		},
	}

	cfg := cataloger.DefaultConfig()
	cfg.Search.Scope = source.AllLayersScope

	packageCatalog, relationships, theDistro, err := syft.CatalogPackages(src, cfg)
	if err != nil {
		return "", fmt.Errorf("failed to catalog packages: %w", err)
	}

	result.Artifacts.Packages = packageCatalog
	result.Artifacts.LinuxDistribution = theDistro
	result.Relationships = relationships

	b, err := format.Encode(result, syftjson.NewFormatEncoder())
	if err != nil {
		return "", fmt.Errorf("failed to encode result: %w", err)
	}

	// Parse the JSON string
	var data interface{}
	err = json.Unmarshal([]byte(b), &data)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	indentedJSON, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if config.SaveJSON {
		fileName := utils.GenerateFileName(imageTag, "syft")
		file, err := os.Create(fileName)
		if err != nil {
			return "", fmt.Errorf("failed to create or open file: %w", err)
		}
		defer file.Close()

		_, err = file.Write(indentedJSON)
		if err != nil {
			return "", fmt.Errorf("failed to write JSON to file: %w", err)
		}
		log.Printf("JSON syft data has been written to %s", fileName)
	}

	stereoscope.Cleanup()

	return string(indentedJSON), nil
}
