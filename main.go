package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

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

var imageTag string

// ConsumerGroupHandler represents a Sarama consumer group consumer
type ConsumerGroupHandler struct{}

// Setup is run at the beginning of a new session, before ConsumeClaim
func (ConsumerGroupHandler) Setup(kafka.ConsumerGroupSession) error { return nil }

// Cleanup is run at the end of a session, once all ConsumeClaim goroutines have exited
func (ConsumerGroupHandler) Cleanup(kafka.ConsumerGroupSession) error { return nil }

// ConsumeClaim must start a consumer loop of ConsumerGroupClaim's Messages().
func (ConsumerGroupHandler) ConsumeClaim(session kafka.ConsumerGroupSession, claim kafka.ConsumerGroupClaim) error {
	// loop over the messages in the claim
	for message := range claim.Messages() {
		fmt.Printf("Message topic:%q partition:%d offset:%d value:%s\n",
			message.Topic, message.Partition, message.Offset, string(message.Value))
		session.MarkMessage(message, "")
		imageTag = string(message.Value)
	}

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
	imageTag := os.Args[1]

	config := kafka.NewConfig()
	config.Consumer.Offsets.Initial = kafka.OffsetOldest
	brokers := []string{os.Getenv("KAFKA_BROKER")}
	topic := []string{os.Getenv("KAFKA_TOPIC")}
	consumergroup := "console-consumer-28827"
	ctx := context.Background()

	fmt.Println(brokers, topic, ctx)
	fmt.Println(consumergroup)
	//fmt.Println(config)

	/*
		consumer, err := kafka.NewConsumerGroup(brokers, consumergroup, config)
		if err != nil {
			fmt.Println("Error creating consumer:", err)
			return
		}
		defer consumer.Close()
	*/
	for {
		/*
			handler := ConsumerGroupHandler{}

				err := consumer.Consume(ctx, topic, handler)
				if err != nil {
					fmt.Println("Error consuming:", err)
					return
				}
		*/

		fmt.Println(imageTag)
		// Run Syft on the image

		/*
			syftOut, err := exec.Command("syft", "--scope", "all-layers", fmt.Sprint(imageTag), "-o", "json=syftout.json").Output() // #nosec G204
			if err != nil {
				fmt.Println("Error running Syft:", err)
				return
			}*/

		// Create a new Syft scanner.

		scope, err := source.Detect(imageTag, source.DefaultDetectConfig())
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(scope)

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
			// TODO: we should have helper functions for getting this built from exported library functions
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

		//fmt.Println(string((b)))

		// Encode the scan results to JSON.
		syftOut, err := json.Marshal(string(b))
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		os.Exit(1)
		fmt.Print(syftOut)
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

	}
}
