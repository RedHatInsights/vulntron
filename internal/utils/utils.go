package utils

import (
	"fmt"
	"strings"
	"time"
)

// DebugPrint prints debug messages
func DebugPrint(format string, args ...interface{}) {
	message := fmt.Sprintf("DEBUG: "+format, args...)
	fmt.Println(message)
}

// GenerateFileName generates a file name based on value and input
func GenerateFileName(value, input string) string {
	lastElement := value
	if parts := strings.Split(value, "/"); len(parts) > 0 {
		lastElement = parts[len(parts)-1]
	}

	currentTime := time.Now().Format("2006-01-02_15:04:05")
	return fmt.Sprintf("%s_%s_%s.json", lastElement, input, currentTime)
}
