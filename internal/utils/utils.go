package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Prints debug messages
func DebugPrint(format string, args ...interface{}) {
	message := fmt.Sprintf("DEBUG: "+format, args...)
	fmt.Println(message)
}

// Generates a file name based on value and input
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
		DebugPrint("Folder created successfully.")
	} else if err != nil {
		fmt.Println("Error checking folder existence:", err)
		os.Exit(1)
	} else {
		DebugPrint("Folder already exists.")
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
