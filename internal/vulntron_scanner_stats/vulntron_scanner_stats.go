package vulntronscannerstats

import (
	"log"
	"time"
)

// Holds statistics related to the scanning process
type ScannerStats struct {
	Start         time.Time
	End           time.Time
	PodsScanned   int
	ImagesScanned int
	ScanningTools int
}

// Initialize a new ScannerStats object with the start time set to the current time
func NewScannerStats() *ScannerStats {
	return &ScannerStats{
		Start: time.Now(),
	}
}

// Set the end time of the scanning process to the current time
func (s *ScannerStats) Finish() {
	s.End = time.Now()
}

// Calculate the total time taken for the scanning process
func (s *ScannerStats) Duration() time.Duration {
	return s.End.Sub(s.Start)
}

// Log the summary of the scanning process
func (s *ScannerStats) Print() {
	log.Printf("Scanning complete: Scanned %d pods with %d images using %d scanning tools in %v\n",
		s.PodsScanned, s.ImagesScanned/s.ScanningTools, s.ScanningTools, s.Duration())
}
