package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RedHatInsights/Vulntron/internal/config"
)

// Prints debug messages
func DebugPrint(config config.VulntronConfig, format string, args ...interface{}) {

	// Construct log message with timestamp
	logMessage := fmt.Sprintf("[%s] DEBUG: "+format, append([]interface{}{time.Now().Format(time.RFC3339)}, args...)...)

	// Print to stdout if enabled
	if config.Logging.Stdout {
		fmt.Println(logMessage)
	}

	// Print to log file if enabled
	if config.Logging.LogFile {
		logFilePath := config.Logging.LogFileLocation + config.Logging.LogFileName

		// Create the directory if it doesn't exist
		err := os.MkdirAll(filepath.Dir(logFilePath), os.ModePerm)
		if err != nil {
			log.Printf("Error creating directory: %v", err)
			return
		}

		// Create the log file if it doesn't exist
		if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
			file, err := os.Create(logFilePath)
			if err != nil {
				log.Printf("Error creating log file: %v", err)
				return
			}
			file.Close()
		}

		file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			// If unable to open log file, log the error to stderr
			log.Printf("Error opening log file: %v", err)
			return
		}
		defer file.Close()

		// Write log message to file
		if _, err := fmt.Fprintln(file, logMessage); err != nil {
			// If unable to write to log file, log the error to stderr
			log.Printf("Error writing to log file: %v", err)
		}
	}
}

// Generates a file name
func GenerateFileName(value, input string) string {
	lastElement := value
	if parts := strings.Split(value, "/"); len(parts) > 0 {
		lastElement = parts[len(parts)-1]
	}

	folderPath := "/tmp/vulntron/"

	// Check if the folder exists
	if _, err := os.Stat(folderPath); os.IsNotExist(err) {
		// Folder does not exist, create it
		err := os.Mkdir(folderPath, 0755)
		if err != nil {
			fmt.Println("Error creating folder:", err)
			os.Exit(1)
		}
		//DebugPrint("Folder created successfully.")
	} else if err != nil {
		fmt.Println("Error checking folder existence:", err)
		os.Exit(1)
	} else {
		//DebugPrint("Folder already exists.")
	}

	currentTime := time.Now().Format("2006-01-02_15:04:05")
	return fmt.Sprintf("/tmp/vulntron/%s_%s_%s.json", lastElement, input, currentTime)
}

func PrettyString(str string) (string, error) {
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, []byte(str), "", " "); err != nil {
		return "", err
	}
	return prettyJSON.String(), nil
}

func CompareLists(list1, list2 []string) bool {
	// Create maps to store the counts of occurrences for each list
	countMap1 := make(map[string]int)
	countMap2 := make(map[string]int)

	// Populate count maps for list1
	for _, item := range list1 {
		countMap1[item]++
	}

	// Populate count maps for list2
	for _, item := range list2 {
		countMap2[item]++
	}

	// Check if the counts match for each item
	for item, count := range countMap1 {
		if countMap2[item] != count {
			return false
		}
	}

	// Check if both lists contain the same unique elements
	return len(countMap1) == len(countMap2)
}
