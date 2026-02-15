package lib

import (
	"log"
	"time"
)

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

// withRetry executes fn up to maxAttempts times with exponential backoff.
// Returns nil on first success or the last error after all attempts fail.
func withRetry(maxAttempts int, baseDelay time.Duration, label string, fn func() error) error {
	var lastErr error
	for i := 0; i < maxAttempts; i++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		if i < maxAttempts-1 {
			delay := baseDelay * time.Duration(1<<uint(i))
			log.Printf("%s attempt %d/%d failed, retrying in %v: %v", label, i+1, maxAttempts, delay, lastErr)
			time.Sleep(delay)
		}
	}
	return lastErr
}
