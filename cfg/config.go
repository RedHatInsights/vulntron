package config

import (
	"os"
)

const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "mypassword"
	dbname   = "mydb"
)

brokers := []string{os.Getenv("KAFKA_BROKER")}
topic := os.Getenv("KAFKA_TOPIC")


