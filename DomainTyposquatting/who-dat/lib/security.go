package lib

import (
	"log"

	"github.com/glaslos/ssdeep"
	"github.com/glaslos/tlsh"
)

// ComputeSSDeep calculates the SSDeep fuzzy hash for the given data.
func ComputeSSDeep(data []byte) string {
	hash, err := ssdeep.FuzzyBytes(data)
	if err != nil {
		log.Printf("SSDeep hash computation failed: %v", err)
		return ""
	}
	return hash
}

// ComputeTLSH calculates the TLSH locality-sensitive hash for the given data.
// Requires at least 256 bytes of input with sufficient complexity.
func ComputeTLSH(data []byte) string {
	hash, err := tlsh.HashBytes(data)
	if err != nil {
		log.Printf("TLSH hash computation failed: %v", err)
		return ""
	}
	return hash.String()
}
