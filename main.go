package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	kafka "github.com/Shopify/sarama"
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

func debugPrint(format string, args ...interface{}) {
	message := fmt.Sprintf("DEBUG: "+format, args...)
	fmt.Println(message)
}

func generateSyftFileName(value string) string {
	lastElement := value
	if parts := strings.Split(value, "/"); len(parts) > 0 {
		lastElement = parts[len(parts)-1]
	}

	currentTime := time.Now().Format("2006-01-02_15:04:05")
	return fmt.Sprintf("%s_syft_%s_.json", lastElement, currentTime)
}

// ConsumerGroupHandler represents a Sarama consumer group consumer
type ConsumerGroupHandler struct{}

// Setup is run at the beginning of a new session, before ConsumeClaim
func (ConsumerGroupHandler) Setup(kafka.ConsumerGroupSession) error { return nil }

// Cleanup is run at the end of a session, once all ConsumeClaim goroutines have exited
func (ConsumerGroupHandler) Cleanup(kafka.ConsumerGroupSession) error { return nil }

// runSyft goroutine
func runSyft(message *kafka.ConsumerMessage) {
	// Implement your logic here
	debugPrint("Running syft for message: %s\n", message.Value)
	var imageTag string = string(message.Value)

	scope, err := source.Detect(imageTag, source.DefaultDetectConfig())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	debugPrint("Detected source: %s", scope)

	src, err := scope.NewSource(source.DefaultDetectionSourceConfig())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
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
		fmt.Println(err)
		os.Exit(1)
	}

	result.Artifacts.Packages = packageCatalog
	result.Artifacts.LinuxDistribution = theDistro
	result.Relationships = relationships

	b, err := format.Encode(result, syftjson.NewFormatEncoder())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Encode the scan results to JSON.
	syftOut, err := json.Marshal(string(b))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	//fmt.Print(string(syftOut))

	// Create or open the file with the last element as the name
	fileName := generateSyftFileName(string(message.Value))
	file, err := os.Create(fileName)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// Write syftOut content to the file
	_, err = file.Write(syftOut)
	if err != nil {
		panic(err)
	}

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
			runSyft(message)
		}(message)
	}

	// Wait for all goroutines to finish
	wg.Wait()

	return nil
}

func main() {
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
	//imageTag := os.Args[1]

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
}

/*

	// Run Grype on the image
	grypeOut, err := exec.Command("grype", "--scope", "all-layers", fmt.Sprint(imageTag), "-o", "json", "--file", "grypeout.json").Output() // #nosec G204
	if err != nil {
		fmt.Println("Error running Grype:", err)
		return
	}

	// Insert the results into the "scan_results" table
	_, err = db.Exec("INSERT INTO scan_results (image_tag, syft_output, grype_output) VALUES ($1, $2, $3)", imageTag, string(syftOut), string(grypeOut))
	if err != nil {
		fmt.Println("Error inserting results into the database:", err)
		return
	}
	fmt.Println("Results stored in the database.")

*/
/*
	}
}
*/
