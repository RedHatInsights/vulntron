package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/RedHatInsights/Vulntron/config"

	kafka "github.com/Shopify/sarama"
	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	grype_db "github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	_ "github.com/lib/pq"
)

const (
	host     = "localhost"
	port     = 5432
	user     = "user"
	password = "password"
	dbname   = "vulntrondb"
)

// DebugPrint prints debug messages
func debugPrint(format string, args ...interface{}) {
	message := fmt.Sprintf("DEBUG: "+format, args...)
	fmt.Println(message)
}

// GenerateFileName generates a file name based on value and input
func generateFileName(value, input string) string {
	lastElement := value
	if parts := strings.Split(value, "/"); len(parts) > 0 {
		lastElement = parts[len(parts)-1]
	}

	currentTime := time.Now().Format("2006-01-02_15:04:05")
	return fmt.Sprintf("%s_%s_%s.json", lastElement, input, currentTime)
}

// handleErr prints an error message and returns true if the error is not nil
func handleErr(message string, err error) bool {
	if err != nil {
		fmt.Printf("%s: %v\n", message, err)
		os.Exit(1)
		return true
	}
	return false
}

// ConsumerGroupHandler represents a Sarama consumer group consumer
type ConsumerGroupHandler struct{}

// Setup is run at the beginning of a new session, before ConsumeClaim
func (ConsumerGroupHandler) Setup(kafka.ConsumerGroupSession) error { return nil }

// Cleanup is run at the end of a session, once all ConsumeClaim goroutines have exited
func (ConsumerGroupHandler) Cleanup(kafka.ConsumerGroupSession) error { return nil }

func runGrype(config config.GrypeConfig, message string) (string, error) {
	// TODO: make `loading DB` and `gathering packages` work in parallel
	// https://github.com/anchore/grype/blob/7e8ee40996ba3a4defb5e887ab0177d99cd0e663/cmd/root.go#L240

	dbConfig := grype_db.Config{
		DBRootDir:           config.DBRootDir,
		ListingURL:          config.ListingURL,
		ValidateByHashOnGet: config.ValidateByHashOnGet,
	}

	store, dbStatus, _, err := grype.LoadVulnerabilityDB(dbConfig, true)
	if err != nil {
		return "", fmt.Errorf("failed to load vulnerability DB: %w", err)
	}

	debugPrint("Running grype for message: %s\n", message)
	imageTag := string(message)

	scope, err := source.Detect(imageTag, source.DefaultDetectConfig())
	if err != nil {
		return "", fmt.Errorf("failed to detect source: %w", err)
	}

	debugPrint("Detected source: %s", scope)

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
		// TODO: automate
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
		return "", fmt.Errorf("failed to analyze packages: %w", err)
	}

	vulnerabilityMatcher := grype.VulnerabilityMatcher{
		Store:          *store,
		Matchers:       matcher.NewDefaultMatchers(matcher.Config{}),
		NormalizeByCVE: true,
	}

	allMatches, ignoredMatches, err := vulnerabilityMatcher.FindMatches(packages, context)

	// We can ignore ErrAboveSeverityThreshold since we are not setting the FailSeverity on the matcher.
	if err != nil {
		return "", fmt.Errorf("failed to find vulnerabilities: %w", err)
	}
	id := clio.Identification{
		Name:    "awesome",
		Version: "v1.0.0",
	}

	doc, err := models.NewDocument(id, packages, context, *allMatches, ignoredMatches, store.MetadataProvider, nil, dbStatus)
	if err != nil {
		return "", fmt.Errorf("failed to create document: %w", err)
	}
	// Encode the scan results to JSON.
	syftOut, err := json.Marshal(doc.Matches)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Create or open the file with the last element as the name
	fileName := generateFileName(imageTag, "grype")
	file, err := os.Create(fileName)
	if err != nil {
		return "", fmt.Errorf("failed to create or open file: %w", err)
	}
	defer file.Close()

	// Write syftOut content to the file
	_, err = file.Write(syftOut)
	if err != nil {
		return "", fmt.Errorf("failed to write to file: %w", err)
	}

	debugPrint("JSON grype data has been written to %s", fileName)

	// Return JSON output
	return string(syftOut), nil
}

func runSyft(config config.SyftConfig, message string) (string, error) {
	debugPrint("Running syft for message: %s\n", message)
	imageTag := string(message)

	scope, err := source.Detect(imageTag, source.DefaultDetectConfig())
	if err != nil {
		return "", fmt.Errorf("failed to detect source: %w", err)
	}
	debugPrint("Detected source: %s", scope)

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

	// Create or open the file with the last element as the name
	fileName := generateFileName(imageTag, "syft")
	file, err := os.Create(fileName)
	if err != nil {
		return "", fmt.Errorf("failed to create or open file: %w", err)
	}
	defer file.Close()

	// Parse the JSON string
	var data interface{}
	err = json.Unmarshal([]byte(b), &data)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	// MarshalIndent for human-readable JSON with an indentation of 2 spaces
	indentedJSON, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Write the indented JSON to the file
	_, err = file.Write(indentedJSON)
	if err != nil {
		return "", fmt.Errorf("failed to write JSON to file: %w", err)
	}

	debugPrint("JSON syft data has been written to %s", fileName)

	// Return JSON output
	return string(indentedJSON), nil
}

// ConsumeClaim must start a consumer loop of ConsumerGroupClaim's Messages().
func (ConsumerGroupHandler) ConsumeClaim(session kafka.ConsumerGroupSession, claim kafka.ConsumerGroupClaim) error {
	var wg sync.WaitGroup

	for message := range claim.Messages() {
		wg.Add(1)
		go func(message *kafka.ConsumerMessage) {
			defer wg.Done()

			fmt.Printf("Message topic:%q partition:%d offset:%d\n", message.Topic, message.Partition, message.Offset)
			session.MarkMessage(message, "")

			// Call the runSyft function for each consumed message
			//runSyft(message)
			//runGrype(message)
		}(message)
	}

	// Wait for all goroutines to finish
	wg.Wait()

	return nil
}

var (
	runType   string
	cfgFile   string
	timestamp string
	imageName string
	component string
	db        *sql.DB
)

func init() {
	// Define command-line flags
	flag.StringVar(&cfgFile, "config", "config.yaml", "Config file")
	flag.StringVar(&runType, "type", "auto", "Message type: kafka or auto")
	flag.StringVar(&timestamp, "timestamp", "", "Timestamp")
	flag.StringVar(&imageName, "imagename", "", "Image name")
	flag.StringVar(&component, "component", "", "Component name")
}

func main() {
	flag.Parse()

	// Read configuration from file
	config, err := config.ReadConfig(cfgFile)
	if err != nil {
		fmt.Printf("Error reading config file: %v\n", err)
		os.Exit(1)
	}

	// Connect to the PostgreSQL database
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)
	fmt.Println("PSQL config: ", psqlInfo)

	db, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		fmt.Println("Error connecting to the database:", err)
		return
	}
	defer db.Close()

	// Check the value of the -type flag
	switch runType {
	case "kafka":
		fmt.Println("Selected message type: Kafka")
		config := kafka.NewConfig()
		config.Consumer.Return.Errors = true
		config.Consumer.Offsets.Initial = kafka.OffsetOldest
		brokers := []string{os.Getenv("KAFKA_BROKER")}
		topic := []string{os.Getenv("KAFKA_TOPIC")}
		consumergroup := "console-consumer-28827"

		debugPrint("Brokers: %s", brokers)
		debugPrint("Consumer group: %s", consumergroup)

		group, err := kafka.NewConsumerGroup(brokers, consumergroup, config)
		if err != nil {
			panic(err)
		}
		defer func() { _ = group.Close() }()

		// Track errors
		go func() {
			for err := range group.Errors() {
				fmt.Println("ERROR", err)
			}
		}()

		// Iterate over consumer sessions.
		ctx := context.Background()
		for {
			handler := ConsumerGroupHandler{}

			// `Consume` should be called inside an infinite loop, when a
			// server-side rebalance happens, the consumer session will need to be
			// recreated to get the new claims
			err := group.Consume(ctx, topic, handler)
			if err != nil {
				panic(err)
			}
		}

	case "auto":
		fmt.Println("Selected message type: Auto")

		imageTag := imageName

		// Run syft
		syftOutput, err := runSyft(config.Syft, imageTag)
		if err != nil {
			fmt.Println("Error running Syft:", err)
			os.Exit(1)
		}

		// Run grype
		grypeOutput, err := runGrype(config.Grype, imageTag)
		if err != nil {
			fmt.Println("Error running Grype:", err)
			os.Exit(1)
		}
		// Check if timestamp, image name, and component are provided
		if timestamp == "" || imageName == "" || component == "" {
			fmt.Println("Error: --timestamp, --imagename, and --component are required for database insert.")
		} else {
			// Insert into the database
			_, err = db.Exec("INSERT INTO deployments (image_name, deployment_date, component_name, syft_output, grype_output) VALUES ($1, $2, $3, $4, $5)",
				imageName, timestamp, component, syftOutput, grypeOutput)
			if err != nil {
				fmt.Println("Error inserting into the database:", err)
				os.Exit(1)
			}
		}

	default:
		fmt.Println("Invalid message type. Please use either 'kafka' or 'auto'.")
		os.Exit(1)
	}

}
