package vulntronscannerstats

import (
	"log"
	"time"
)

type ScannerStats struct {
	Start         time.Time
	End           time.Time
	PodsScanned   int
	ImagesScanned int
	ScanningTools int
}

func NewScannerStats() *ScannerStats {
	return &ScannerStats{
		Start: time.Now(),
	}
}

func (s *ScannerStats) Finish() {
	s.End = time.Now()
}

func (s *ScannerStats) Duration() time.Duration {
	return s.End.Sub(s.Start)
}

func (s *ScannerStats) Print() {
	log.Printf("Scanning complete: Scanned %d pods with %d images using %d scanning tools in %v\n",
		s.PodsScanned, s.ImagesScanned/s.ScanningTools, s.ScanningTools, s.Duration())
}
