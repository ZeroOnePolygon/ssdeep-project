package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ScanResult holds cleanly parsed file detection fields for JSON/CSV output
type ScanResult struct {
	SHA256   string `json:"sha256"`
	FilePath string `json:"file_path"`
	Type     string `json:"type"` // "ALERT" or "WARN"
	Ssdeep   string `json:"ssdeep"`
	Message  string `json:"-"` // json:"-" ซ่อน field นี้ใน JSON โดยไม่ต้อง copy struct ใหม่
}

// Regex to capture and drop terminal color codes
var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// cleanANSIMessage strips terminal formatting to make output safe for files
func cleanANSIMessage(msg string) string {
	msg = strings.TrimPrefix(msg, "\r") // Remove carriage returns
	return ansiRegex.ReplaceAllString(msg, "")
}

// exportToJSON saves findings as an indented JSON array in the exact requested order
func exportToJSON(filename string, results []ScanResult) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	bw := bufio.NewWriter(file)
	defer bw.Flush()

	encoder := json.NewEncoder(bw)
	encoder.SetIndent("", "  ")

	// Encode ScanResult
	return encoder.Encode(results)
}

// exportToCSV saves findings into an Excel-friendly CSV table with exact JSON key matching
func exportToCSV(filename string, results []ScanResult) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	bw := bufio.NewWriter(file)
	defer bw.Flush()

	writer := csv.NewWriter(bw)
	defer writer.Flush()

	if err := writer.Write([]string{"sha256", "file_path", "type", "ssdeep"}); err != nil {
		return err
	}

	for i := range results {
		row := []string{results[i].SHA256, results[i].FilePath, results[i].Type, results[i].Ssdeep}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func handleExportMenu(results []ScanResult) {
	if len(results) == 0 {
		return
	}

	fmt.Printf("\n%s[+] Found %d ALERT/WARN items. Would you like to export the report?%s\n", ColorGreen, len(results), ColorReset)
	fmt.Printf("  %s[1]%s Export to JSON (scan_report.json)\n", ColorGreen, ColorReset)
	fmt.Printf("  %s[2]%s Export to CSV (scan_report.csv)\n", ColorGreen, ColorReset)
	fmt.Printf("  %s[3]%s Skip Export and return to menu\n", ColorGreen, ColorReset)
	fmt.Printf("\n%sSelect an export option (1-3) > %s", ColorYellow, ColorReset)
	scanner := bufio.NewScanner(os.Stdin)
	var choice string
	if scanner.Scan() {
		choice = strings.TrimSpace(scanner.Text())
	}

	switch choice {
	case "1":
		filename := "scan_report.json"
		if err := exportToJSON(filename, results); err != nil {
			fmt.Printf("%s[!] Failed to export JSON: %v%s\n", ColorRed, err, ColorReset)
		} else {
			fmt.Printf("%s[+] Report successfully saved to %s%s\n", ColorGreen, filename, ColorReset)
		}
	case "2":
		filename := "scan_report.csv"
		if err := exportToCSV(filename, results); err != nil {
			fmt.Printf("%s[!] Failed to export CSV: %v%s\n", ColorRed, err, ColorReset)
		} else {
			fmt.Printf("%s[+] Report successfully saved to %s%s\n", ColorGreen, filename, ColorReset)
		}
	default:
		fmt.Printf("%s[*] Skipping export step.%s\n", ColorCyan, ColorReset)
	}
}
