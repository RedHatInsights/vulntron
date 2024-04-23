package main

import (
	"context"
	"log"
	"os"

	"github.com/RedHatInsights/Vulntron/internal/vulntron_dd"
)

func main() {
	ctx := context.Background()
	client, err := vulntron_dd.TokenInit(os.Getenv("DEFECT_DOJO_USERNAME"), os.Getenv("DEFECT_DOJO_PASSWORD"), os.Getenv("DEFECT_DOJO_URL"), &ctx)
	if err != nil {
		log.Fatalf("Error initializing DefectDojo client: %v", err)
	}

	err = vulntron_dd.DeleteProductTypes(&ctx, client)
	if err != nil {
		log.Fatalf("Error deleting ProductTypes: %v", err)
	}
}
