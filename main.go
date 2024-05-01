package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/RedHatInsights/Vulntron/internal/config"
	vulntronauto "github.com/RedHatInsights/Vulntron/internal/vulntron_auto"
	"github.com/RedHatInsights/Vulntron/internal/vulntron_dd"
	vulntronkafka "github.com/RedHatInsights/Vulntron/internal/vulntron_kafka"
	dd "github.com/doximity/defect-dojo-client-go"
)

func main() {
	// Command-line flag setup for specifying the configuration file location
	var cfgFile string
	flag.StringVar(&cfgFile, "config", "config.yaml", "Config file location")
	flag.Parse()

	// Load configuration from the specified file
	cfg, err := loadConfiguration(cfgFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Setup logging according to the configuration
	setupLogging(cfg.Vulntron)

	// Establish a new context for future API calls
	ctx := context.Background()

	// Initialize DefectDojo API client
	client, err := initializeDefectDojoClient(&ctx)
	if err != nil {
		log.Fatalf("Failed to initialize DefectDojo client: %v", err)
	}

	// Validate system settings from DefectDojo against configuration
	validateSystemSettings(&ctx, client, cfg)
	if cfg.DefectDojo.SlackNotifications {
		// Validate Slack notification settings
		validateSlackNotificationSettings(&ctx, client, cfg)
	}

	// Process data based on the run type specified in configuration
	switch cfg.Vulntron.RunType {
	case "auto":
		vulntronauto.ProcessAutoMode(cfg, &ctx, client)
	case "kafka":
		vulntronkafka.ProcessKafkaMode()
	default:
		log.Fatalf("Invalid run type '%s': use 'auto' or 'kafka'", cfg.Vulntron.RunType)
	}
}

// Initialize logging based on configuration
func setupLogging(cfg config.VulntronConfig) {
	// Set log flags
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var logFile *os.File
	if cfg.Logging.LogFile {
		logPath := filepath.Join(cfg.Logging.LogFileLocation, cfg.Logging.LogFileName)

		// Ensure directory exists
		if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
			log.Fatalf("Error creating directory for log file: %v", err)
		}

		// Open log file
		var err error
		logFile, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Error opening log file: %v", err)
		}

		// Set multi-writer to write both to file and stdout
		log.SetOutput(io.MultiWriter(os.Stdout, logFile))
	} else {
		// Set output to stdout only
		log.SetOutput(os.Stdout)
	}

	log.Printf("Logging successfully initialized")
}

// Load configuration into predefined structure
func loadConfiguration(filePath string) (config.Config, error) {
	config, err := config.ReadConfig(filePath)
	if err != nil {
		return config, fmt.Errorf("error reading config file: %v", err)
	}
	timeStamp := time.Now().Format("2006-01-02_15-04-05")
	config.Vulntron.Logging.LogFileName = fmt.Sprintf("Grype_eng_%s.log", timeStamp)
	return config, nil
}

// Initialize and return a DefectDojo client
func initializeDefectDojoClient(ctx *context.Context) (*dd.ClientWithResponses, error) {
	client, err := vulntron_dd.TokenInit(os.Getenv("DEFECT_DOJO_USERNAME"), os.Getenv("DEFECT_DOJO_PASSWORD"), os.Getenv("DEFECT_DOJO_URL"), ctx)
	if err != nil {
		log.Fatalf("Error initializing DefectDojo client: %v", err)
	}
	return client, nil
}

// Check and update the system settings in DefectDojo to match the configuration
func validateSystemSettings(ctx *context.Context, client *dd.ClientWithResponses, config config.Config) {
	systemSettings, err := vulntron_dd.ListSystemSettings(ctx, client)
	if err != nil {
		log.Fatalf("Error getting system settings: %v", err)
	}
	for _, pt := range *systemSettings.Results {
		if pt.MaxDupes == nil ||
			*pt.EnableDeduplication != config.DefectDojo.EnableDeduplication ||
			*pt.DeleteDuplicates != config.DefectDojo.DeleteDuplicates ||
			*pt.MaxDupes != config.DefectDojo.MaxDuplicates {
			log.Printf("Defect Dojo System settings are not correct!")
			err = vulntron_dd.UpdateSystemSettings(
				ctx,
				client,
				*pt.Id,
				config.DefectDojo.EnableDeduplication,
				config.DefectDojo.DeleteDuplicates,
				config.DefectDojo.MaxDuplicates)
			if err != nil {
				log.Fatalf("Error setting system settings: %v", err)
			}
		} else {
			log.Printf("Defect Dojo System settings match config.")
		}
	}
}

// Check and update the slack settings in DefectDojo to match the configuration
func validateSlackNotificationSettings(ctx *context.Context, client *dd.ClientWithResponses, config config.Config) {
	systemSettings, err := vulntron_dd.ListSystemSettings(ctx, client)
	if err != nil {
		log.Fatalf("Error getting system settings: %v", err)
	}
	slackChannel := os.Getenv("DEFECT_DOJO_SLACK_CHANNEL")
	slackToken := os.Getenv("DEFECT_DOJO_SLACK_OAUTH")

	for _, pt := range *systemSettings.Results {
		if *pt.EnableSlackNotifications != config.DefectDojo.SlackNotifications ||
			*pt.SlackChannel != slackChannel ||
			*pt.SlackToken != slackToken {
			log.Printf("Defect Dojo System slack settings are not correct!")
			err = vulntron_dd.UpdateSlackSettings(
				ctx,
				client,
				*pt.Id,
				slackChannel,
				slackToken,
			)
			if err != nil {
				log.Fatalf("Error setting system settings: %v", err)
			}
		} else {
			log.Printf("Defect Dojo Slack System settings match config.")
		}
	}
}
