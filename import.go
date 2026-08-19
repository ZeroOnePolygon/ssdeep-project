package main

import (
	"bufio"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func addSig(malname, fullHash string) {
	if err := initDatabases(); err != nil {
		fmt.Printf("%s[!] DB Init Error: %v%s\n", ColorRed, err, ColorReset)
		return
	}

	conn, err := getSigDBConnection()
	if err != nil {
		fmt.Printf("%s[!] DB Connect Error: %v%s\n", ColorRed, err, ColorReset)
		return
	}
	defer conn.Close()

	parts := strings.Split(fullHash, ":")
	if len(parts) == 0 {
		fmt.Printf("%s[!] Invalid hash format.%s\n", ColorRed, ColorReset)
		return
	}

	blockSize, err := strconv.Atoi(parts[0])
	if err != nil {
		fmt.Printf("%s[!] Invalid block size in hash.%s\n", ColorRed, ColorReset)
		return
	}

	// Duplicate check before insert
	var count int
	err = conn.QueryRow("SELECT COUNT(*) FROM signatures WHERE ssdeep_full = ?", fullHash).Scan(&count)
	if err != nil {
		fmt.Printf("%s[!] DB Query Error: %v%s\n", ColorRed, err, ColorReset)
		return
	}

	if count > 0 {
		fmt.Printf("%s[!] Duplicate: '%s' already exists in signatures (skipped).%s\n", ColorYellow, malname, ColorReset)
		return
	}

	_, err = conn.Exec("INSERT INTO signatures (malware_name, block_size, ssdeep_full) VALUES (?, ?, ?)",
		malname, blockSize, fullHash)

	if err != nil {
		fmt.Printf("%s[!] DB Insert Error: %v%s\n", ColorRed, err, ColorReset)
	} else {
		fmt.Printf("%s[+] Added '%s' (Block Size: %d) to signatures.%s\n", ColorGreen, malname, blockSize, ColorReset)
	}
}

func importSigs(filepath string) {
	if err := initDatabases(); err != nil {
		fmt.Printf("%s[!] DB Init Error: %v%s\n", ColorRed, err, ColorReset)
		return
	}

	// เปิด Connection ตรงนี้ที่เดียว และส่งต่อให้ทุกฟังก์ชันย่อย
	conn, err := getSigDBConnection()
	if err != nil {
		fmt.Printf("%s[!] DB Connect Error: %v%s\n", ColorRed, err, ColorReset)
		return
	}
	defer conn.Close()

	lowerPath := strings.ToLower(filepath)
	if strings.HasSuffix(lowerPath, ".json") {
		parseJsonFile(filepath, conn)
	} else if strings.HasSuffix(lowerPath, ".sql") {
		parseSqlFile(filepath, conn)
	} else if strings.HasSuffix(lowerPath, ".csv") {
		parseCsvFile(filepath, conn)
	} else {
		fmt.Printf("%s[!] Unsupported file extension. Use .json, .sql, or .csv.%s\n", ColorRed, ColorReset)
	}
}

type SigItem struct {
	Name   string `json:"name"`
	Family string `json:"family"`
	Ssdeep string `json:"ssdeep"`
}

func parseJsonFile(filepath string, dbConn *sql.DB) {
	fmt.Printf("%s[*] Reading JSON file: %s ...%s\n", ColorCyan, filepath, ColorReset)

	file, err := os.Open(filepath)
	if err != nil {
		fmt.Printf("%s[!] File Open Error: %v%s\n", ColorRed, err, ColorReset)
		return
	}
	defer file.Close()

	var data []SigItem
	if err := json.NewDecoder(file).Decode(&data); err != nil {
		fmt.Printf("%s[!] JSON Parse Error: %v%s\n", ColorRed, err, ColorReset)
		return
	}

	fmt.Printf("%s[*] Successfully loaded: %d items.%s\n", ColorCyan, len(data), ColorReset)
	fmt.Printf("%s[*] Analyzing and importing to database...%s\n", ColorCyan, ColorReset)

	importLoop(data, dbConn)
}

func parseCsvFile(filepath string, dbConn *sql.DB) {
	fmt.Printf("%s[*] Reading CSV file: %s...%s\n", ColorCyan, filepath, ColorReset)

	file, err := os.Open(filepath)
	if err != nil {
		fmt.Printf("%s[!] File Open Error: %v%s\n", ColorRed, err, ColorReset)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1

	var data []SigItem
	lineNum := 0

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("%s[!] CSV Parse Error at line %d: %v%s\n", ColorRed, lineNum+1, err, ColorReset)
			continue
		}
		lineNum++

		for i := range record {
			record[i] = strings.TrimSpace(record[i])
		}

		switch len(record) {
		case 2:
			if lineNum == 1 && !strings.Contains(record[1], ":") {
				continue
			}
			data = append(data, SigItem{Name: record[0], Ssdeep: record[1]})

		case 3:
			if lineNum == 1 && !strings.Contains(record[2], ":") {
				continue
			}
			data = append(data, SigItem{Name: record[0], Family: record[1], Ssdeep: record[2]})

		default:
			continue
		}
	}

	if len(data) == 0 {
		fmt.Printf("%s[!] No valid data found in CSV file.%s\n", ColorRed, ColorReset)
		return
	}

	fmt.Printf("%s[*] Successfully loaded: %d items.%s\n", ColorCyan, len(data), ColorReset)
	fmt.Printf("%s[*] Importing to database...%s\n", ColorCyan, ColorReset)

	importLoop(data, dbConn)
}

func parseSqlFile(filepath string, dbConn *sql.DB) {
	fmt.Printf("%s[*] Reading file: %s%s\n", ColorCyan, filepath, ColorReset)

	file, err := os.Open(filepath)
	if err != nil {
		fmt.Printf("%s[!] File Open Error: %v%s\n", ColorRed, err, ColorReset)
		return
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	valuePattern := regexp.MustCompile(`\((.*?)\)`)
	fieldsPattern := regexp.MustCompile(`'(.*?)'|NULL`)

	var data []SigItem

	for {
		line, err := reader.ReadString('\n')
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "INSERT INTO `malware_signatures`") || strings.HasPrefix(trimmed, "INSERT INTO malware_signatures") {
			matches := valuePattern.FindAllString(line, -1)

			for _, match := range matches {
				match = strings.TrimPrefix(match, "(")
				match = strings.TrimSuffix(match, ")")

				fields := fieldsPattern.FindAllStringSubmatch(match, -1)

				var cleanFields []string
				for _, f := range fields {
					if f[0] != "NULL" {
						cleanFields = append(cleanFields, f[1])
					}
				}

				if len(cleanFields) >= 3 {
					data = append(data, SigItem{
						Name:   cleanFields[0],
						Family: cleanFields[1],
						Ssdeep: cleanFields[2],
					})
				}
			}
		}

		if err != nil {
			if err != io.EOF {
				fmt.Printf("%s[!] Error reading SQL file: %v%s\n", ColorRed, err, ColorReset)
			}
			break
		}
	}

	importLoop(data, dbConn)
}

func importLoop(data []SigItem, dbConn *sql.DB) {
	// --- Duplicate Check: Load all existing ssdeep hashes into memory ---
	existingHashes := make(map[string]struct{})
	rows, err := dbConn.Query("SELECT ssdeep_full FROM signatures")
	if err == nil {
		for rows.Next() {
			var h string
			if err := rows.Scan(&h); err == nil {
				existingHashes[h] = struct{}{}
			}
		}
		rows.Close()
	}

	tx, err := dbConn.Begin()
	if err != nil {
		fmt.Printf("%s[!] Failed to start transaction: %v%s\n", ColorRed, err, ColorReset)
		return
	}

	stmt, err := tx.Prepare("INSERT INTO signatures (malware_name, block_size, ssdeep_full) VALUES (?, ?, ?)")
	if err != nil {
		tx.Rollback()
		fmt.Printf("%s[!] Failed to prepare statement: %v%s\n", ColorRed, err, ColorReset)
		return
	}
	defer stmt.Close()

	totalAdded := 0
	totalSkipped := 0
	totalDuplicate := 0

	for _, item := range data {
		if item.Ssdeep == "" || !strings.Contains(item.Ssdeep, ":") {
			totalSkipped++
			continue
		}

		// ตรวจสอบ Duplicate โดยเช็คว่าคีย์มีอยู่ใน Map หรือไม่
		if _, exists := existingHashes[item.Ssdeep]; exists {
			totalDuplicate++
			continue
		}

		parts := strings.Split(item.Ssdeep, ":")
		blockSize, err := strconv.Atoi(parts[0])
		if err != nil {
			totalSkipped++
			continue
		}

		displayName := item.Name
		if item.Family != "" && strings.ToLower(item.Family) != "unknown" {
			displayName = fmt.Sprintf("%s (%s)", item.Name, item.Family)
		}

		_, err = stmt.Exec(displayName, blockSize, item.Ssdeep)
		if err == nil {
			existingHashes[item.Ssdeep] = struct{}{} // บันทึกลง Memory Map เพื่อป้องกันข้อมูลซ้ำซ้อนภายใน Batch เดียวกัน
			totalAdded++
		} else {
			totalSkipped++
		}
	}

	// บันทึกข้อมูลลงฐานข้อมูลจริง
	if err := tx.Commit(); err != nil {
		fmt.Printf("%s[!] Failed to commit transaction: %v%s\n", ColorRed, err, ColorReset)
		return
	}

	fmt.Printf("%s[+] Import successful: %d signatures.%s\n", ColorGreen, totalAdded, ColorReset)
	if totalDuplicate > 0 {
		fmt.Printf("%s[!] Duplicates skipped: %d items (already in database).%s\n", ColorYellow, totalDuplicate, ColorReset)
	}
	if totalSkipped > 0 {
		fmt.Printf("%s[!] Invalid/missing ssdeep entries skipped: %d items.%s\n", ColorRed, totalSkipped, ColorReset)
	}
}
