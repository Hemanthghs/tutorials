package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

func GenerateCode(secret string) (string, error) {
	// Current time interval (30 seconds is standard)
	interval := time.Now().Unix() / 30
	// Prepare the secret - normalize and decode from base32
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	secretBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("invalid secret format: %v", err)
	}
	// Generate HMAC-SHA1
	return generateTOTP(secretBytes, interval), nil
}

func generateTOTP(secret []byte, interval int64) string {
	// Convert interval to byte array
	intervalBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(intervalBytes, uint64(interval))

	// Generate HMAC-SHA1
	h := hmac.New(sha1.New, secret)
	h.Write(intervalBytes)
	hash := h.Sum(nil)

	// Dynamic truncation
	offset := hash[len(hash)-1] & 0xf
	truncatedHash := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	// Reduce truncatedHash to 6-digit code
	code := truncatedHash % 1000000

	return fmt.Sprintf("%06d", code)
}

func main() {
	// Load .env file
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file:", err)
		os.Exit(1)
	}

	// Get the secret key from environment variables
	secret := os.Getenv("TOTP_SECRET")
	if secret == "" {
		fmt.Println("TOTP_SECRET environment variable not found in .env file")
		os.Exit(1)
	}

	fmt.Println("Printing TOTP codes every 30 seconds.")

	var lastInterval int64 = -1

	for {
		now := time.Now()
		currentInterval := now.Unix() / 30

		// Only generate a new code if we've moved to a new 30-second interval
		if currentInterval > lastInterval {
			code, err := GenerateCode(secret)
			if err != nil {
				fmt.Printf("Error generating code: %v\n", err)
				os.Exit(1)
			}

			nextIntervalStart := (currentInterval + 1) * 30
			validFor := nextIntervalStart - now.Unix()

			timestamp := now.Format("15:04:05")
			fmt.Printf("[%s] TOTP: %s (valid for %d seconds)\n", timestamp, code, validFor)

			lastInterval = currentInterval
		}

		time.Sleep(500 * time.Millisecond)
	}
}
