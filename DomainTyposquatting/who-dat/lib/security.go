package lib

import (
	"log"

	"github.com/glaslos/ssdeep"
	"github.com/glaslos/tlsh"
)

// Minimum bytes required for meaningful hash computation.
const (
	minSSDeepBytes = 64
	minTLSHBytes   = 256
)

// ComputeSSDeep calculates the SSDeep fuzzy hash for the given data.
// Returns empty string if data is too small for a meaningful hash.
func ComputeSSDeep(data []byte) string {
	if len(data) < minSSDeepBytes {
		log.Printf("SSDeep skipped: data too small (%d bytes, need %d)", len(data), minSSDeepBytes)
		return ""
	}
	hash, err := ssdeep.FuzzyBytes(data)
	if err != nil {
		log.Printf("SSDeep hash computation failed: %v", err)
		return ""
	}
	return hash
}

// ComputeTLSH calculates the TLSH locality-sensitive hash for the given data.
// Returns empty string if data is below the 256-byte minimum.
func ComputeTLSH(data []byte) string {
	if len(data) < minTLSHBytes {
		log.Printf("TLSH skipped: data too small (%d bytes, need %d)", len(data), minTLSHBytes)
		return ""
	}
	hash, err := tlsh.HashBytes(data)
	if err != nil {
		log.Printf("TLSH hash computation failed: %v", err)
		return ""
	}
	return hash.String()
}
