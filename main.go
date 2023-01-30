package main

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"

	"github.com/Shopify/sarama"
	_ "github.com/lib/pq"
)

const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "mypassword"
	dbname   = "mydb"
)

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

	brokers := []string{os.Getenv("KAFKA_BROKER")}
	topic := os.Getenv("KAFKA_TOPIC")

	consumer, err := sarama.NewConsumer(brokers, nil)
	if err != nil {
		fmt.Println("Error creating consumer:", err)
		return
	}
	defer consumer.Close()

	partitionConsumer, err := consumer.ConsumePartition(topic, 0, sarama.OffsetNewest)
	if err != nil {
		fmt.Println("Error creating partition consumer:", err)
		return
	}
	defer partitionConsumer.Close()

	for {
		select {
		case msg := <-partitionConsumer.Messages():
			imageTag := string(msg.Value)
			fmt.Println("Received image tag:", imageTag)

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
}
