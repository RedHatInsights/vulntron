package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"

	kafka "github.com/Shopify/sarama"
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
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		fmt.Println("Error connecting to the database:", err)
		return
	}
	defer db.Close()

	// Get the Quay image tag from the command line (for practice)
	// imageTag := os.Args[1]

	config := kafka.NewConfig()
	config.Consumer.Offsets.Initial = kafka.OffsetOldest
	brokers := []string{os.Getenv("KAFKA_BROKER")}
	topic := []string{os.Getenv("KAFKA_TOPIC")}
	consumergroup := "vulntron"
	ctx := context.Background()

	consumer, err := kafka.NewConsumerGroup(brokers, consumergroup, config)
	if err != nil {
		fmt.Println("Error creating consumer:", err)
		return
	}
	defer consumer.Close()

	for {
		handler := ConsumerGroupHandler{}

		err := consumer.Consume(ctx, topic, handler)
		if err != nil {
			fmt.Println("Error consuming:", err)
			return
		}

		// Run Syft on the image
		syftOut, err := exec.Command("syft", "--scope", "all-layers", fmt.Sprint(imageTag), "-o", "json=syftout.json").Output() // #nosec G204
		if err != nil {
			fmt.Println("Error running Syft:", err)
			return
		}

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
	}
}
