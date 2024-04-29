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

	_ "github.com/lib/pq"
)

var (
	cfgFile string
)

func init() {
	// Command-line flags
	flag.StringVar(&cfgFile, "config", "config.yaml", "Config file location")
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

func loadConfiguration(filePath string) (config.Config, error) {
	config, err := config.ReadConfig(filePath)
	if err != nil {
		return config, fmt.Errorf("error reading config file: %v", err)
	}
	timeStamp := time.Now().Format("2006-01-02_15-04-05")
	config.Vulntron.Logging.LogFileName = fmt.Sprintf("Grype_eng_%s.log", timeStamp)
	return config, nil
}

func initializeDefectDojoClient(ctx *context.Context) (*dd.ClientWithResponses, error) {
	client, err := vulntron_dd.TokenInit(os.Getenv("DEFECT_DOJO_USERNAME"), os.Getenv("DEFECT_DOJO_PASSWORD"), os.Getenv("DEFECT_DOJO_URL"), ctx)
	if err != nil {
		log.Fatalf("Error initializing DefectDojo client: %v", err)
	}
	return client, nil
}

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

func validateSlackNotificationSettings(ctx *context.Context, client *dd.ClientWithResponses, config config.Config) {
	systemSettings, err := vulntron_dd.ListSystemSettings(ctx, client)
	if err != nil {
		log.Fatalf("Error getting system settings: %v", err)
	}
	slackChannel := os.Getenv("DEFECT_DOJO_SLACK_CHANNEL")
	slackToken := os.Getenv("DEFECT_DOJO_SLACK_OAUTH")

	for _, pt := range *systemSettings.Results {
		if pt.MaxDupes == nil ||
			*pt.EnableSlackNotifications != config.DefectDojo.SlackNotifications ||
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

func main() {

	flag.Parse()

	config, err := loadConfiguration(cfgFile)
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	ctx := context.Background()
	client, err := initializeDefectDojoClient(&ctx)
	if err != nil {
		log.Fatalf("Error initializing DefectDojo client: %v", err)
	}

	setupLogging(config.Vulntron)

	validateSystemSettings(&ctx, client, config)

	if config.DefectDojo.EnableDeduplication {
		validateSlackNotificationSettings(&ctx, client, config)
	}

	if config.Vulntron.RunType == "auto" {
		vulntronauto.ProcessAutoMode(config, &ctx, client)
	} else if config.Vulntron.RunType == "kafka" {
		vulntronkafka.ProcessKafkaMode()
	} else {
		log.Fatalf("Invalid message type. Please use either 'kafka' or 'auto'.")
	}
}
