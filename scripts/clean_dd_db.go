package main

import (
	"context"
	"log"
	"os"

	"github.com/RedHatInsights/Vulntron/internal/vulntron_dd"
)

func main() {
	// Create a new context for the cleanup application
	ctx := context.Background()

	// Initialize a DefectDojo client
	client, err := vulntron_dd.TokenInit(os.Getenv("DEFECT_DOJO_USERNAME"), os.Getenv("DEFECT_DOJO_PASSWORD"), os.Getenv("DEFECT_DOJO_URL"), &ctx)
	if err != nil {
		log.Fatalf("Error initializing DefectDojo client: %v", err)
	}

	// Attempt to delete all ProductTypes in DefectDojo using the initialized client
	err = vulntron_dd.DeleteProductTypes(&ctx, client)
	if err != nil {
		log.Fatalf("Error deleting ProductTypes: %v", err)
	}
}
