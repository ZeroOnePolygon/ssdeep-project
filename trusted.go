package main

import (
	"bufio"
	_ "embed"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

//go:embed trusted_publishers.txt
var embeddedPublishers string

var (
	trustedPublishers []string
	publishersMu      sync.RWMutex // ป้องกัน Data Race เวลา Worker อ่านพร้อมกัน
)

// LoadTrustedPublishers โหลดรายชื่อผู้พัฒนาที่เชื่อถือได้
func LoadTrustedPublishers() {
	// 1. โหลดจาก Embedded Text
	list := parsePublisherList(strings.NewReader(embeddedPublishers))

	// 2. ถ้ามีไฟล์ Override บนดิสก์ ให้ใช้ไฟล์บนดิสก์แทนทั้งหมด
	if f, err := os.Open("trusted_publishers.txt"); err == nil {
		defer f.Close()
		overrides := parsePublisherList(f)
		if len(overrides) > 0 {
			list = overrides
		}
	}

	// 3. อัปเดตข้อมูลแบบ Thread-safe
	publishersMu.Lock()
	trustedPublishers = list
	publishersMu.Unlock()

	fmt.Printf("%s[*] Trusted publishers loaded: %d entries%s\n", ColorCyan, len(list), ColorReset)
}

// parsePublisherList อ่านและแกะรายชื่อ Publisher จาก io.Reader ใดๆ (ทั้ง File และ String)
func parsePublisherList(r io.Reader) []string {
	var result []string
	sc := bufio.NewScanner(r)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		// ข้ามบรรทัดว่าง และบรรทัดที่เป็น Comment (#)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		result = append(result, strings.ToLower(line))
	}

	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "%s[!] Error parsing trusted publishers: %v%s\n", ColorRed, err, ColorReset)
	}

	return result
}

// isTrustedPublisher ตรวจสอบว่า CompanyName ตรงกับ Publisher ที่เชื่อถือได้หรือไม่
func isTrustedPublisher(company string) bool {
	company = strings.TrimSpace(company)
	if company == "" {
		return false // Fast path: ถ้าไม่มีชื่อ Publisher ให้ข้ามทันที
	}

	publishersMu.RLock()
	defer publishersMu.RUnlock()

	lower := strings.ToLower(company)
	for _, trusted := range trustedPublishers {
		if strings.Contains(lower, trusted) {
			return true
		}
	}
	return false
}
