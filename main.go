package main

import (
	"database/sql"
	"fmt"
	"os/exec"

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

	// Get the Quay image tag
	imageTag := "quay.io/myorg/myimage:latest"

	// Run Syft on the image
	syftOut, err := exec.Command("syft", "image", imageTag).Output()
	if err != nil {
		fmt.Println("Error running Syft:", err)
		return
	}

	// Run Grype on the image
	grypeOut, err := exec.Command("grype", "image", imageTag).Output()
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
