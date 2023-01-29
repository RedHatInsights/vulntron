package config

import{
	"os"
}

const dbconfig (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "mypassword"
	dbname   = "mydb"
)

const kafka (
	brokers := []string{os.Getenv("KAFKA_BROKER")}
	topic := os.Getenv("KAFKA_TOPIC")
)

