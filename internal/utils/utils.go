package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

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
