package main

import (
	"bufio"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dmitryikh/leaves"
	"github.com/glaslos/ssdeep"
)

// ANSI Color Constants
const (
	ColorRed    = "\033[91m"
	ColorGreen  = "\033[92m"
	ColorYellow = "\033[93m"
	ColorCyan   = "\033[96m"
	ColorReset  = "\033[0m"
)

// Execution Parameters
const (
	MinFileSize     = 4*1024 + 1
	MaxFileSize     = 50 * 1024 * 1024
	MLSafeThreshold = 0.587
)

var (
	OfflineMode      bool
	dbWriteMutex     sync.Mutex
	Threshold        = 85
	xgbModel         *leaves.Ensemble
	scanResults      []ScanResult
	SuppressCleanVT  = true
	TargetExtensions = makeDefaultExtensions()

	DefaultTargetExtensions = makeDefaultExtensions()

	ExcludedDirs = map[string]bool{
		"winsxs": true, "$recycle.bin": true, "system volume information": true,
		"$windows.~bt": true, "$windows.~ws": true, "proc": true, "sys": true,
		"dev": true, "run": true, "snap": true, "lost+found": true,
	}

	bufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 8192)
		},
	}
)

func makeDefaultExtensions() map[string]bool {
	return map[string]bool{
		".com": true, ".msi": true, ".msp": true, ".scr": true, ".pif": true,
		".cpl": true, ".msc": true, ".exe": true, ".dll": true, ".sys": true,
		".ps1": true, ".bat": true, ".cmd": true, ".vbs": true, ".vbe": true,
		".jse": true, ".wsf": true, ".hta": true, ".inf": true, ".lnk": true,
		".url": true, ".docm": true, ".xlsm": true, ".pptm": true, ".rtf": true,
		".sh": true, ".py": true, ".jar": true, ".so": true, ".dmg": true,
		".pkg": true, ".command": true, ".js": true, ".psm1": true, ".psd1": true,
	}
}

type Signature struct {
	MalwareName string
	SigHash     string
}

type CacheResult struct {
	MTime    int64
	IsThreat bool
	Message  string
	SHA256   string
	Ssdeep   string
}

type ScanStats struct {
	TotalScanned   atomic.Int64
	ThreatsFound   atomic.Int64
	SkippedFilter  atomic.Int64
	SkippedCache   atomic.Int64
	SkippedVTClean atomic.Int64
	SkippedSigned  atomic.Int64
	SkippedTrusted atomic.Int64
	SkippedMLClean atomic.Int64
}

type PEMetadata struct {
	NumSections int
	BlockSize   int
	Company     string
}

type fileJob struct {
	path  string
	mtime int64
}

// Zero-Allocation Target Extension Checker
func hasTargetExtension(path string, targets map[string]bool) bool {
	idx := strings.LastIndexByte(path, '.')
	if idx == -1 || idx == len(path)-1 {
		return false
	}
	ext := path[idx:]
	if targets[ext] {
		return true
	}
	return targets[strings.ToLower(ext)]
}

func checkInternetAccess() bool {
	conn, err := net.DialTimeout("tcp", "www.virustotal.com:443", 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func initMLModel() error {
	fmt.Printf("%s[*] Loading XGBoost malware model...%s\n", ColorCyan, ColorReset)
	model, err := leaves.XGEnsembleFromFile("malware_model.bin", false)
	if err != nil {
		return err
	}
	xgbModel = model
	return nil
}

// Single-Pass PE Metadata Extractor (Replaces 3 separate file opens)
func getPEMetadata(path string) PEMetadata {
	meta := PEMetadata{}
	file, err := pe.Open(path)
	if err != nil {
		return meta
	}
	defer file.Close()

	meta.NumSections = len(file.Sections)

	switch opt := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		meta.BlockSize = int(opt.SectionAlignment)
	case *pe.OptionalHeader64:
		meta.BlockSize = int(opt.SectionAlignment)
	}

	meta.Company, _ = getPECompanyName(path)
	return meta
}

func calculateEntropy(filePath string) float64 {
	file, err := os.Open(filePath)
	if err != nil {
		return 0
	}
	defer file.Close()

	var byteCounts [256]float64
	var totalBytes float64

	bufObj := bufPool.Get()
	buf := bufObj.([]byte)
	defer bufPool.Put(bufObj)

	for {
		n, err := file.Read(buf)
		if n > 0 {
			for i := 0; i < n; i++ {
				byteCounts[buf[i]]++
			}
			totalBytes += float64(n)
		}
		if err == io.EOF {
			break
		}
	}

	if totalBytes == 0 {
		return 0
	}

	var entropy float64
	for _, count := range byteCounts {
		if count > 0 {
			p := count / totalBytes
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// Corrected Positional Mapping for XGBoost Model
func extractFeatures(fileSize float64, entropy float64, blockSize float64, numSections float64) []float64 {
	return []float64{
		fileSize,    // 1. file_size_bytes
		entropy,     // 2. file_entropy
		blockSize,   // 3. block_size
		numSections, // 4. num_sections
	}
}

func configureExtensions() {
	fmt.Printf("\n%s=== Configure Target Extensions ===%s\n", ColorCyan, ColorReset)
	fmt.Printf("%sEnter EXACT extensions to scan separated by commas (e.g., .exe, .dll).\nType 'all' to scan default set, or press ENTER to keep current > %s", ColorYellow, ColorReset)

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			fmt.Printf("%s[!] Input reading error: %v%s\n", ColorRed, err, ColorReset)
		}
		return
	}

	input := strings.TrimSpace(strings.ToLower(scanner.Text()))
	if input == "" {
		fmt.Printf("%s[*] Keeping current extension settings.%s\n", ColorYellow, ColorReset)
		return
	}

	scanResults = nil

	if input == "all" {
		newMap := make(map[string]bool, len(DefaultTargetExtensions))
		for k, v := range DefaultTargetExtensions {
			newMap[k] = v
		}
		TargetExtensions = newMap
		fmt.Printf("%s[+] Scanner set to default predefined extensions.%s\n", ColorGreen, ColorReset)
		return
	}

	rawExts := strings.Split(input, ",")
	newExts := make(map[string]bool, len(rawExts))
	active := make([]string, 0, len(rawExts))

	for _, e := range rawExts {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		if !newExts[e] {
			newExts[e] = true
			active = append(active, e)
		}
	}

	if len(newExts) == 0 {
		fmt.Printf("%s[!] No valid extensions provided. Keeping existing configuration.%s\n", ColorRed, ColorReset)
		return
	}

	TargetExtensions = newExts
	fmt.Printf("%s[+] Target extensions updated to: %s%s\n", ColorGreen, strings.Join(active, ", "), ColorReset)
}

func isExcludedDir(dirPath string) bool {
	baseName := strings.ToLower(filepath.Base(dirPath))
	return ExcludedDirs[baseName]
}

func ScanTargets(directories []string) {
	scanResults = nil
	var validDirs []string
	for _, d := range directories {
		if _, err := os.Stat(d); err == nil {
			validDirs = append(validDirs, d)
		}
	}
	if len(validDirs) == 0 {
		fmt.Printf("%s[!] Error: No valid directories to scan.%s\n", ColorRed, ColorReset)
		os.Exit(1)
	}

	if err := initDatabases(); err != nil {
		fmt.Printf("%s[!] DB Init Error: %v%s\n", ColorRed, err, ColorReset)
		os.Exit(1)
	}

	sigConn, err := getSigDBConnection()
	if err != nil {
		fmt.Printf("%s[!] DB Connect Error: %v%s\n", ColorRed, err, ColorReset)
		os.Exit(1)
	}
	defer sigConn.Close()

	cacheConn, err := getCacheDBConnection()
	if err != nil {
		fmt.Printf("%s[!] DB Connect Error: %v%s\n", ColorRed, err, ColorReset)
		os.Exit(1)
	}
	defer cacheConn.Close()

	fmt.Printf("%s[*] Loading cache data into memory...%s\n", ColorCyan, ColorReset)
	memoryCache, err := loadCache(cacheConn)
	if err != nil {
		fmt.Printf("%s[!] Cache Load Error: %v%s\n", ColorRed, err, ColorReset)
	}

	updatedCache := make(map[string]CacheResult, 10000)

	fmt.Printf("%s[*] Pre-loading signatures...%s\n", ColorCyan, ColorReset)
	sigMap := make(map[int][]Signature)
	totalSigs := 0
	rows, err := sigConn.Query(`SELECT block_size, malware_name, ssdeep_full FROM signatures`)
	if err == nil {
		for rows.Next() {
			var bSize int
			var mName, sHash string
			if err := rows.Scan(&bSize, &mName, &sHash); err == nil {
				sigMap[bSize] = append(sigMap[bSize], Signature{MalwareName: mName, SigHash: sHash})
				totalSigs++
			}
		}
		rows.Close()
	}

	var activeExts []string
	for ext, active := range TargetExtensions {
		if active {
			activeExts = append(activeExts, ext)
		}
	}
	sort.Strings(activeExts)

	fmt.Printf("%s[*] Total signatures : %d items.%s\n", ColorCyan, totalSigs, ColorReset)
	fmt.Printf("%s[*] Current Threshold: %d%%%s\n", ColorCyan, Threshold, ColorReset)
	fmt.Printf("%s[*] Target Extensions: %s%s\n", ColorCyan, strings.Join(activeExts, ", "), ColorReset)
	fmt.Println()

	if OfflineMode {
		fmt.Printf("%s[*] Offline Mode forced by user flag. VirusTotal disabled.%s\n", ColorYellow, ColorReset)
	} else {
		fmt.Printf("%s[*] Checking network connection to VirusTotal...%s\n", ColorCyan, ColorReset)
		if checkInternetAccess() {
			fmt.Printf("%s[+] Online Mode active. VirusTotal enabled.%s\n", ColorGreen, ColorReset)
		} else {
			OfflineMode = true
			fmt.Printf("%s[!] Cannot reach VirusTotal. Auto-switching to Offline Mode.%s\n", ColorYellow, ColorReset)
		}
	}
	fmt.Println()

	stats := ScanStats{}
	startTime := time.Now()

	jobs := make(chan fileJob, 5000)
	var wg sync.WaitGroup
	var statsMutex sync.Mutex

	numWorkers := runtime.NumCPU() * 2
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				func() {
					fileName := filepath.Base(job.path)
					dirPath := filepath.Dir(job.path)

					f, err := os.Open(job.path)
					if err != nil {
						return
					}
					defer f.Close()

					shaHasher := sha256.New()
					tee := io.TeeReader(f, shaHasher)

					hash, err := ssdeep.FuzzyReader(tee)
					if err != nil || hash == "" {
						return
					}

					fileSha := hex.EncodeToString(shaHasher.Sum(nil))

					parts := strings.Split(hash, ":")
					if len(parts) < 3 {
						return
					}
					blockSize, err := strconv.Atoi(parts[0])
					if err != nil {
						return
					}

					threatDetected := false
					var finalAlertMsg string
					var alertType string
					blocksToScan := [3]int{blockSize / 2, blockSize, blockSize * 2}

					// Consolidated single PE header parse
					peMeta := getPEMetadata(job.path)

				SearchLoop:
					for _, bSize := range blocksToScan {
						for idx := range sigMap[bSize] {
							sig := &sigMap[bSize][idx]
							score, err := ssdeep.Distance(hash, sig.SigHash)

							if err == nil && score >= Threshold {

								// Layer 1: Authenticode
								if hasValidAuthenticode(job.path) {
									stats.SkippedSigned.Add(1)
									break SearchLoop
								}

								// Layer 2: Trusted publisher check
								if peMeta.Company != "" && isTrustedPublisher(peMeta.Company) {
									finalAlertMsg = fmt.Sprintf("\n%s[WARN]%s %s | Path: %s | Match: %d%% | Family: %s | ⚠ Unverified Publisher: %s%s",
										ColorYellow, ColorReset, fileName, dirPath, score, sig.MalwareName, peMeta.Company, ColorReset)
									fmt.Println(finalAlertMsg)
									stats.SkippedTrusted.Add(1)
									threatDetected = true
									alertType = "WARN"
									break SearchLoop
								}

								// Layer 3: ML filter (XGBoost)
								if xgbModel != nil {
									info, err := f.Stat()
									if err == nil {
										entropy := calculateEntropy(job.path)
										features := extractFeatures(
											float64(info.Size()),
											entropy,
											float64(peMeta.BlockSize),
											float64(peMeta.NumSections),
										)

										if len(features) > 0 {
											// Direct slice pass without re-allocating features64
											prediction := xgbModel.PredictSingle(features, 0)
											if prediction < MLSafeThreshold {
												stats.SkippedMLClean.Add(1)
												break SearchLoop
											}
										}
									}
								}

								// Layer 4: VirusTotal check
								vtScore := ""
								if OfflineMode {
									vtScore = " | VT: Skipped (Offline)"
								} else if len(vtKeys) > 0 {
									mal, total, vtErr := CheckVTScore(job.path)
									if vtErr != nil {
										if vtErr.Error() == "not found on VT" {
											vtScore = " | VT: Unknown"
										} else if strings.Contains(vtErr.Error(), "429") {
											vtScore = " | VT: Rate Limit (429)"
										} else if strings.Contains(vtErr.Error(), "401") {
											vtScore = " | VT: Invalid Key (401)"
										} else {
											vtScore = fmt.Sprintf(" | VT: Error (%v)", vtErr)
										}
									} else if mal == 0 {
										if !SuppressCleanVT {
											cleanMsg := fmt.Sprintf("\n%s[CLEAN]%s %s | Path: %s | Match: %d%% | Family: %s | VT: 0/%d%s",
												ColorGreen, ColorReset, fileName, dirPath, score, sig.MalwareName, total, ColorReset)
											fmt.Println(cleanMsg)
										}
										stats.SkippedVTClean.Add(1)
										break SearchLoop
									} else {
										vtScore = fmt.Sprintf(" | VT: %d/%d", mal, total)
									}
								}

								publisherInfo := ""
								if peMeta.Company != "" {
									publisherInfo = fmt.Sprintf(" | Publisher: %s", peMeta.Company)
								}

								finalAlertMsg = fmt.Sprintf("\n%s[ALERT] %s | Path: %s | Match: %d%% | Family: %s%s%s%s",
									ColorRed, fileName, dirPath, score, sig.MalwareName, vtScore, publisherInfo, ColorReset)
								fmt.Println(finalAlertMsg)
								stats.ThreatsFound.Add(1)
								threatDetected = true
								alertType = "ALERT"
								break SearchLoop
							}
						}
					}
					stats.TotalScanned.Add(1)
					if stats.TotalScanned.Load()%100 == 0 {
						fmt.Printf("\rScanned: %d files...", stats.TotalScanned.Load())
					}

					if threatDetected {
						statsMutex.Lock()
						scanResults = append(scanResults, ScanResult{
							SHA256:   fileSha,
							FilePath: job.path,
							Type:     alertType,
							Ssdeep:   hash,
							Message:  cleanANSIMessage(finalAlertMsg),
						})
						statsMutex.Unlock()
					}

					var cacheSha, cacheSsdeep string
					if threatDetected {
						cacheSha = fileSha
						cacheSsdeep = hash
					}

					statsMutex.Lock()
					updatedCache[job.path] = CacheResult{
						MTime:    job.mtime,
						IsThreat: threatDetected,
						Message:  finalAlertMsg,
						SHA256:   cacheSha,
						Ssdeep:   cacheSsdeep,
					}

					var mapToFlush map[string]CacheResult
					if len(updatedCache) >= 2000 {
						mapToFlush = updatedCache
						updatedCache = make(map[string]CacheResult, 10000)
					}
					statsMutex.Unlock()

					if mapToFlush != nil {
						dbWriteMutex.Lock()
						_ = batchUpdateCache(cacheConn, mapToFlush)
						dbWriteMutex.Unlock()
					}
				}()
			}
		}()
	}

	for _, dir := range validDirs {
		filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			// 1. Fast directory filtering
			if d.IsDir() {
				if isExcludedDir(path) {
					return filepath.SkipDir
				}
				return nil
			}

			// 2. Zero-allocation extension check (Executed BEFORE os.Stat/d.Info)
			if !hasTargetExtension(path, TargetExtensions) {
				stats.SkippedFilter.Add(1)
				return nil
			}

			if !d.Type().IsRegular() {
				return nil
			}

			info, err := d.Info()
			if err != nil {
				stats.SkippedFilter.Add(1)
				return nil
			}

			if info.Size() < MinFileSize || info.Size() > MaxFileSize {
				stats.SkippedFilter.Add(1)
				return nil
			}

			mtime := info.ModTime().UnixNano()
			cachedEntry, ok := memoryCache[path]

			if ok && cachedEntry.MTime == mtime {
				stats.SkippedCache.Add(1)
				if cachedEntry.IsThreat {
					fmt.Printf("%s\n", cachedEntry.Message)
					resType := "ALERT"
					if strings.Contains(cachedEntry.Message, "[WARN]") {
						resType = "WARN"
						stats.SkippedTrusted.Add(1)
					} else {
						stats.ThreatsFound.Add(1)
					}

					statsMutex.Lock()
					scanResults = append(scanResults, ScanResult{
						SHA256:   cachedEntry.SHA256,
						FilePath: path,
						Type:     resType,
						Ssdeep:   cachedEntry.Ssdeep,
						Message:  cleanANSIMessage(cachedEntry.Message),
					})
					statsMutex.Unlock()
				}
				return nil
			}

			jobs <- fileJob{path: path, mtime: mtime}
			return nil
		})
	}
	close(jobs)
	wg.Wait()

	fmt.Printf("\rScanned: %d files... Done!                    \n", stats.TotalScanned.Load())

	// Flush remaining cache updates to disk
	statsMutex.Lock()
	remainingCache := updatedCache
	updatedCache = nil
	statsMutex.Unlock()

	if len(remainingCache) > 0 {
		fmt.Printf("\n%s[*] Finalizing cache database on disk...%s\n", ColorCyan, ColorReset)
		dbWriteMutex.Lock()
		if err := batchUpdateCache(cacheConn, remainingCache); err != nil {
			fmt.Printf("%s[!] Error updating cache: %v%s\n", ColorRed, err, ColorReset)
		}
		dbWriteMutex.Unlock()
	}

	elapsedTime := time.Since(startTime)
	fmt.Printf("\n%s=== Scan Summary ===%s\n", ColorGreen, ColorReset)
	fmt.Printf("Total files scanned       : %s%d%s\n", ColorCyan, stats.TotalScanned.Load(), ColorReset)
	fmt.Printf("Files skipped (Size/Ext)  : %d\n", stats.SkippedFilter.Load())
	fmt.Printf("Files skipped (Cache)     : %d\n", stats.SkippedCache.Load())
	if stats.SkippedSigned.Load() > 0 {
		fmt.Printf("Suppressed (Authenticode) : %s%d%s\n", ColorGreen, stats.SkippedSigned.Load(), ColorReset)
	}
	if stats.SkippedTrusted.Load() > 0 {
		fmt.Printf("Warnings  (Unverified Pub): %s%d%s\n", ColorYellow, stats.SkippedTrusted.Load(), ColorReset)
	}
	if stats.SkippedMLClean.Load() > 0 {
		fmt.Printf("Suppressed (ML: Low Risk) : %s%d%s\n", ColorGreen, stats.SkippedMLClean.Load(), ColorReset)
	}
	if stats.SkippedVTClean.Load() > 0 {
		fmt.Printf("Suppressed (VT: 0 det.)   : %s%d%s\n", ColorYellow, stats.SkippedVTClean.Load(), ColorReset)
	}
	if stats.ThreatsFound.Load() > 0 {
		fmt.Printf("Threats detected          : %s%d%s\n", ColorRed, stats.ThreatsFound.Load(), ColorReset)
	} else {
		fmt.Printf("Threats detected          : %s0%s\n", ColorGreen, ColorReset)
	}

	mins := int(elapsedTime.Minutes())
	secs := math.Mod(elapsedTime.Seconds(), 60.0)
	if mins > 0 {
		fmt.Printf("Time elapsed        : %s%d minutes %.2f seconds%s\n", ColorCyan, mins, secs, ColorReset)
	} else {
		fmt.Printf("Time elapsed        : %s%.2f seconds%s\n", ColorCyan, secs, ColorReset)
	}

	handleExportMenu(scanResults)
}
