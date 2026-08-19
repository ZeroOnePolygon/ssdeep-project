package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	vtKeys       []string
	vtKeyIdx     int
	vtKeyLock    sync.Mutex
	vtHttpClient = &http.Client{Timeout: 15 * time.Second}
)

// LoadVTKeys loads API keys from vt_keys.txt
func LoadVTKeys() error {
	file, err := os.Open("vt_keys.txt")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	var loadedKeys []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key := strings.TrimSpace(scanner.Text())

		// Remove Null bytes and BOMs
		key = strings.ReplaceAll(key, "\x00", "")
		key = strings.TrimPrefix(key, "\xff\xfe")
		key = strings.TrimPrefix(key, "\xfe\xff")
		key = strings.TrimPrefix(key, "\xef\xbb\xbf")

		if key != "" && !strings.HasPrefix(key, "#") {
			loadedKeys = append(loadedKeys, key)
		}
	}

	vtKeyLock.Lock()
	vtKeys = loadedKeys
	vtKeyLock.Unlock()

	return scanner.Err()
}

func getNextVTKey() string {
	vtKeyLock.Lock()
	defer vtKeyLock.Unlock()
	if len(vtKeys) == 0 {
		return ""
	}
	key := vtKeys[vtKeyIdx]
	vtKeyIdx = (vtKeyIdx + 1) % len(vtKeys)
	return key
}

// CalculateSHA256 returns the SHA-256 hash of a file
func CalculateSHA256(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// VTResponse represents the relevant parts of the VT API v3 response
type VTResponse struct {
	Data struct {
		Attributes struct {
			Ssdeep            string `json:"ssdeep"`
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Harmless   int `json:"harmless"`
			} `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}

func doVTRequest(url string) ([]byte, error) {
	vtKeyLock.Lock()
	numKeys := len(vtKeys)
	vtKeyLock.Unlock()

	if numKeys == 0 {
		return nil, fmt.Errorf("no VT API keys configured")
	}

	var lastErr error

	for i := 0; i < numKeys; i++ {
		apiKey := getNextVTKey()

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err // Request creation failed
		}
		req.Header.Add("x-apikey", apiKey)

		resp, err := vtHttpClient.Do(req)
		if err != nil {
			return nil, err // Network level error
		}

		if resp.StatusCode == 429 || resp.StatusCode == 401 { // Rate limited or Unauthorized key
			resp.Body.Close()
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			continue // Try the next key
		}

		if resp.StatusCode == 404 {
			resp.Body.Close()
			return nil, fmt.Errorf("not found on VT")
		} else if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("VT API error: status %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close() // ปิดทันที
		if err != nil {
			return nil, err
		}

		return body, nil
	}

	return nil, fmt.Errorf("all %d keys exhausted (Limit reached). Last Err: %v", numKeys, lastErr)
}

// CheckVTScore queries VT and returns malicious count and total count
func CheckVTScore(filepath string) (int, int, error) {
	hash, err := CalculateSHA256(filepath)
	if err != nil {
		return 0, 0, err
	}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash)
	body, err := doVTRequest(url)
	if err != nil {
		return 0, 0, err
	}

	var vtResp VTResponse
	if err := json.Unmarshal(body, &vtResp); err != nil {
		return 0, 0, err
	}

	stats := vtResp.Data.Attributes.LastAnalysisStats
	malicious := stats.Malicious + stats.Suspicious
	total := stats.Malicious + stats.Suspicious + stats.Undetected + stats.Harmless

	return malicious, total, nil
}

// FetchSsdeepFromVT queries VT API v3 with a SHA256 or SHA1 hash and returns the ssdeep hash.
func FetchSsdeepFromVT(hashInput, malwareName string) error {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hashInput)

	body, err := doVTRequest(url)
	if err != nil {
		return err
	}

	var vtResp VTResponse
	if err := json.Unmarshal(body, &vtResp); err != nil {
		return err
	}

	ssdeepHash := vtResp.Data.Attributes.Ssdeep
	if ssdeepHash == "" {
		return fmt.Errorf("ssdeep hash not available on VT for this file")
	}

	fmt.Printf("%s[+] ssdeep retrieved: %s%s\n", ColorGreen, ssdeepHash, ColorReset)
	addSig(malwareName, ssdeepHash)
	return nil
}
