package vulntron_trivy

import (
	"fmt"
	"log"
	"os/exec"

	"github.com/RedHatInsights/Vulntron/internal/config"
	"github.com/RedHatInsights/Vulntron/internal/utils"
)

// Run a Trivy scan on the specified container image and output to a JSON file
func RunTrivy(cfg config.Config, imageTag string) (string, error) {
	log.Printf("Running Trivy for image: %s", imageTag)

	// Set up the output file path
	outputFilePath := utils.GenerateFileName(imageTag, "trivy")

	// Prepare and execute the Trivy command
	cmd := exec.Command("trivy", "image", "-f", "json", "-o", outputFilePath, imageTag)
	if err := cmd.Run(); err != nil {
		log.Printf("Trivy command failed: %v", err)
		return "", fmt.Errorf("error: Trivy command failed: %w", err)
	}

	log.Printf("Trivy scan results have been written to %s", outputFilePath)
	return outputFilePath, nil
}
