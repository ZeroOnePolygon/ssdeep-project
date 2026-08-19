package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"runtime"

	_ "modernc.org/sqlite"
)

const (
	SigDBPath   = "signatures.db"
	CacheDBPath = "cache.db"
)

func initDatabases() error {
	sigConn, err := getSigDBConnection()
	if err != nil {
		return fmt.Errorf("failed to open signatures DB: %w", err)
	}
	defer sigConn.Close()

	_, err = sigConn.Exec(`
		CREATE TABLE IF NOT EXISTS signatures (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			malware_name TEXT,
			block_size INTEGER,
			ssdeep_full TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_block_size ON signatures(block_size);
		CREATE INDEX IF NOT EXISTS idx_ssdeep_full ON signatures(ssdeep_full);
	`)
	if err != nil {
		return fmt.Errorf("failed to initialize signatures table: %w", err)
	}

	cacheConn, err := getCacheDBConnection()
	if err != nil {
		return fmt.Errorf("failed to open cache DB: %w", err)
	}
	defer cacheConn.Close()

	// อัปเดตใช้ INTEGER สำหรับ is_threat เพื่อความสม่ำเสมอ
	_, err = cacheConn.Exec(`
		CREATE TABLE IF NOT EXISTS scan_cache (
			filepath TEXT PRIMARY KEY,
			mtime INTEGER NOT NULL,
			is_threat INTEGER NOT NULL,
			message TEXT,
			sha256 TEXT,
			ssdeep TEXT
		);
	`)
	if err != nil {
		return fmt.Errorf("failed to initialize cache table: %w", err)
	}

	return nil
}

func getSigDBConnection() (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=synchronous(OFF)&_pragma=journal_mode(MEMORY)&_pragma=temp_store(MEMORY)&_pragma=busy_timeout(5000)", SigDBPath)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	conn.SetMaxOpenConns(runtime.NumCPU())
	return conn, nil
}

func getCacheDBConnection() (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=cache_size(-64000)", CacheDBPath)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	// จำกัด Connection เพื่อความปลอดภัยในการเขียน
	conn.SetMaxOpenConns(1)
	return conn, nil
}

func initCacheDB() error {
	cacheConn, err := getCacheDBConnection()
	if err != nil {
		return fmt.Errorf("failed to open cache DB: %w", err)
	}
	defer cacheConn.Close()
	_, err = cacheConn.Exec(`
		CREATE TABLE IF NOT EXISTS scan_cache (
			filepath TEXT PRIMARY KEY,
			mtime INTEGER NOT NULL,
			is_threat INTEGER NOT NULL,
			message TEXT,
			sha256 TEXT,
			ssdeep TEXT
		);
	`)
	if err != nil {
		return fmt.Errorf("failed to initialize cache table: %w", err)
	}

	return nil
}

func loadCache(db *sql.DB) (map[string]CacheResult, error) {
	// เพิ่มการอ่าน sha256 และ ssdeep จากตาราง scan_cache
	rows, err := db.Query("SELECT filepath, mtime, is_threat, message, sha256, ssdeep FROM scan_cache")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cache := make(map[string]CacheResult, 10000)
	for rows.Next() {
		var filepath string
		var entry CacheResult
		var isThreatInt int
		var msg, sha, ss sql.NullString // ใช้ sql.NullString ป้องกัน error จากค่า NULL

		if err := rows.Scan(&filepath, &entry.MTime, &isThreatInt, &msg, &sha, &ss); err != nil {
			continue
		}

		entry.IsThreat = (isThreatInt == 1)
		entry.Message = msg.String
		entry.SHA256 = sha.String
		entry.Ssdeep = ss.String

		cache[filepath] = entry
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return cache, nil
}

func batchUpdateCache(db *sql.DB, updatedCache map[string]CacheResult) error {
	if len(updatedCache) == 0 {
		return nil
	}

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// เพิ่ม sha256 และ ssdeep เข้าไปในการ INSERT และ UPDATE
	query := `
		INSERT INTO scan_cache (filepath, mtime, is_threat, message, sha256, ssdeep) 
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(filepath) DO UPDATE SET 
			mtime = excluded.mtime,
			is_threat = excluded.is_threat,
			message = excluded.message,
			sha256 = excluded.sha256,
			ssdeep = excluded.ssdeep;
	`
	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for path, entry := range updatedCache {
		isThreatInt := 0
		if entry.IsThreat {
			isThreatInt = 1
		}

		// ส่งตัวแปรเข้าไปใน stmt.Exec ให้ครบทั้ง 6 ตัว
		if _, err := stmt.Exec(path, entry.MTime, isThreatInt, entry.Message, entry.SHA256, entry.Ssdeep); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func clearCacheDB() {
	cacheFile := "cache.db"

	// ตรวจสอบว่ามีไฟล์ cache.db อยู่หรือไม่
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		fmt.Printf("%s[!] Cache database (%s) does not exist.%s\n", ColorYellow, cacheFile, ColorReset)
		return
	}

	// ทำการลบไฟล์
	err := os.Remove(cacheFile)
	if err != nil {
		fmt.Printf("%s[!] Failed to delete %s: %v%s\n", ColorRed, cacheFile, err, ColorReset)
	} else {
		fmt.Printf("%s[+] Successfully deleted %s%s\n", ColorGreen, cacheFile, ColorReset)
	}
}
