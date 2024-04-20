package vulntron_grype

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/RedHatInsights/Vulntron/internal/config"
	"github.com/RedHatInsights/Vulntron/internal/utils"
	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	grype_db "github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func RunGrype(config_g config.GrypeConfig, config_v config.VulntronConfig, message string) (string, string, error) {
	// TODO: make `loading DB` and `gathering packages` work in parallel
	// https://github.com/anchore/grype/blob/7e8ee40996ba3a4defb5e887ab0177d99cd0e663/cmd/root.go#L240

	dbConfig := grype_db.Config{
		DBRootDir:           config_g.DBRootDir,
		ListingURL:          config_g.ListingURL,
		ValidateByHashOnGet: config_g.ValidateByHashOnGet,
	}

	store, dbStatus, _, err := grype.LoadVulnerabilityDB(dbConfig, true)
	if err != nil {
		return "", "", fmt.Errorf("failed to load vulnerability DB: %w", err)
	}

	log.Printf("Running grype for message: %s", message)
	imageTag := string(message)

	scope, err := source.Detect(imageTag, source.DefaultDetectConfig())
	if err != nil {
		return "", "", fmt.Errorf("failed to detect source: %w", err)
	}

	log.Printf("Detected source: %v", scope)

	src, err := scope.NewSource(source.DefaultDetectionSourceConfig())
	if err != nil {
		return "", "", fmt.Errorf("failed to create source: %w", err)
	}

	result := sbom.SBOM{
		Source: src.Describe(),
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "0.96.0",
		},
		// TODO: automate
	}

	cfg := cataloger.DefaultConfig()
	cfg.Search.Scope = source.AllLayersScope

	packageCatalog, relationships, theDistro, err := syft.CatalogPackages(src, cfg)
	if err != nil {
		return "", "", fmt.Errorf("failed to catalog packages: %w", err)
	}

	result.Artifacts.Packages = packageCatalog
	result.Artifacts.LinuxDistribution = theDistro
	result.Relationships = relationships

	providerConfig := pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{
			CatalogingOptions: cataloger.Config{
				Search: cataloger.DefaultSearchConfig(),
			},
			RegistryOptions: source.DefaultDetectionSourceConfig().RegistryOptions,
		},
	}
	providerConfig.CatalogingOptions.Search.Scope = source.AllLayersScope

	packages, context, _, err := pkg.Provide(message, providerConfig)
	if err != nil {
		return "", "", fmt.Errorf("failed to analyze packages: %w", err)
	}

	vulnerabilityMatcher := grype.VulnerabilityMatcher{
		Store:          *store,
		Matchers:       matcher.NewDefaultMatchers(matcher.Config{}),
		NormalizeByCVE: true,
	}

	allMatches, ignoredMatches, err := vulnerabilityMatcher.FindMatches(packages, context)

	if err != nil {
		return "", "", fmt.Errorf("failed to find vulnerabilities: %w", err)
	}
	id := clio.Identification{
		Name:    "grype",
		Version: "0.96.0",
	}

	doc, err := models.NewDocument(id, packages, context, *allMatches, ignoredMatches, store.MetadataProvider, nil, dbStatus)
	if err != nil {
		return "", "", fmt.Errorf("failed to create document: %w", err)
	}
	/*
		// Encode the scan results to JSON.
		syftOut, err := json.Marshal(doc)
		if err != nil {
			return "", fmt.Errorf("failed to marshal JSON: %w", err)
		}*/

	var buf bytes.Buffer
	jsonEncoder := json.NewEncoder(&buf)
	jsonEncoder.SetEscapeHTML(false)

	// Encode the scan results to JSON using the JSON encoder
	if err := jsonEncoder.Encode(doc); err != nil {
		return "", "", fmt.Errorf("failed to encode JSON: %w", err)
	}

	var res string
	var fileName string

	if config_v.SaveJSON {
		fileName = utils.GenerateFileName(imageTag, "grype")
		file, err := os.Create(fileName)
		if err != nil {
			return "", "", fmt.Errorf("failed to create or open file: %w", err)
		}
		defer file.Close()

		res, err := utils.PrettyString(buf.String())
		if err != nil {
			fmt.Println(err)
		}

		// Write syftOut content to the file
		_, err = file.Write([]byte(res))
		if err != nil {
			return "", "", fmt.Errorf("failed to write to file: %w", err)
		}
		log.Printf("JSON grype data has been written to %s", fileName)
	}

	stereoscope.Cleanup()

	return res, fileName, err
}
