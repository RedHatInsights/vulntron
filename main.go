package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	kafka "github.com/Shopify/sarama"
	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	grype_db "github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/grypeerr"
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
	user     = "postgres"
	password = "mypassword"
	dbname   = "mydb"
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
	return fmt.Sprintf("%s_%s_%s_.json", lastElement, input, currentTime)
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

func runGrype(message string) {
	// TODO: make `loading DB` and `gathering packages` work in parallel
	// https://github.com/anchore/grype/blob/7e8ee40996ba3a4defb5e887ab0177d99cd0e663/cmd/root.go#L240

	dbConfig := grype_db.Config{
		DBRootDir:           "/tmp/",
		ListingURL:          "https://toolbox-data.anchore.io/grype/databases/listing.json",
		ValidateByHashOnGet: false,
	}

	store, dbStatus, _, err := grype.LoadVulnerabilityDB(dbConfig, true)
	if handleErr("failed to load vulnerability DB", err) {
		return
	}

	debugPrint("Running grype for message: %s\n", message)
	imageTag := string(message)

	scope, err := source.Detect(imageTag, source.DefaultDetectConfig())
	if handleErr("failed to detect source", err) {
		return
	}
	debugPrint("Detected source: %s", scope)

	src, err := scope.NewSource(source.DefaultDetectionSourceConfig())
	if handleErr("failed to create source", err) {
		return
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
	if handleErr("failed to catalog packages", err) {
		return
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
	if handleErr("failed to analyze packages", err) {
		return
	}

	vulnerabilityMatcher := grype.VulnerabilityMatcher{
		Store:          *store,
		Matchers:       matcher.NewDefaultMatchers(matcher.Config{}),
		NormalizeByCVE: true,
	}

	allMatches, ignoredMatches, err := vulnerabilityMatcher.FindMatches(packages, context)

	// We can ignore ErrAboveSeverityThreshold since we are not setting the FailSeverity on the matcher.
	if err != nil && !errors.Is(err, grypeerr.ErrAboveSeverityThreshold) {
		handleErr("failed to find vulnerabilities", err)
		return
	}

	id := clio.Identification{
		Name:    "awesome",
		Version: "v1.0.0",
	}

	doc, err := models.NewDocument(id, packages, context, *allMatches, ignoredMatches, store.MetadataProvider, nil, dbStatus)
	if handleErr("failed to create document", err) {
		return
	}

	// Encode the scan results to JSON.
	syftOut, err := json.Marshal(doc.Matches)
	if handleErr("failed to marshal JSON", err) {
		return
	}

	// Create or open the file with the last element as the name
	fileName := generateFileName(imageTag, "grype")
	file, err := os.Create(fileName)
	if handleErr("failed to create or open file", err) {
		return
	}
	defer file.Close()

	// Write syftOut content to the file
	_, err = file.Write(syftOut)
	handleErr("failed to write to file", err)
}

// runSyft goroutine
/*
func runSyft(message *kafka.ConsumerMessage) {
	debugPrint("Running syft for message: %s\n", message.Value)
	var imageTag string = string(message.Value)
*/
func runSyft(message string) {
	debugPrint("Running syft for message: %s\n", message)
	imageTag := string(message)

	scope, err := source.Detect(imageTag, source.DefaultDetectConfig())
	if handleErr("failed to detect source", err) {
		return
	}
	debugPrint("Detected source: %s", scope)

	src, err := scope.NewSource(source.DefaultDetectionSourceConfig())
	if handleErr("failed to create source", err) {
		return
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
	if handleErr("failed to catalog packages", err) {
		return
	}

	result.Artifacts.Packages = packageCatalog
	result.Artifacts.LinuxDistribution = theDistro
	result.Relationships = relationships

	b, err := format.Encode(result, syftjson.NewFormatEncoder())
	if handleErr("failed to encode result", err) {
		return
	}

	// Encode the scan results to JSON.
	syftOut, err := json.Marshal(string(b))
	if handleErr("failed to marshal JSON", err) {
		return
	}

	// Create or open the file with the last element as the name
	fileName := generateFileName(imageTag, "syft")
	file, err := os.Create(fileName)
	if handleErr("failed to create or open file", err) {
		return
	}
	defer file.Close()

	// Write syftOut content to the file
	_, err = file.Write(syftOut)
	handleErr("failed to write to file", err)
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
	runType string
)

func init() {
	// Define command-line flags
	flag.StringVar(&runType, "type", "auto", "Message type: kafka or auto")
}

func main() {
	flag.Parse()

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
		// Connect to the PostgreSQL database
		psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)
		fmt.Println("PSQL config: ", psqlInfo)

		db, err := sql.Open("postgres", psqlInfo)
		if err != nil {
			fmt.Println("Error connecting to the database:", err)
			return
		}
		defer db.Close()

		// Get the Quay image tag from the command line (for practice)
		imageTag := os.Args[3]
		runSyft(imageTag)
		runGrype(imageTag)

	default:
		fmt.Println("Invalid message type. Please use either 'kafka' or 'auto'.")
		os.Exit(1)
	}

}
