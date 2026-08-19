package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

func printBanner() {
	banner := `
  _   _                       _    _   _      
 | | | | ___ _   _ _ __ _   _| |___| |_(_) ___ 
 | |_| |/ _ \ | | | '__| | | | / __| __| |/ __|
 |  _  |  __/ |_| | |  | |_| | \__ \ |_| | (__ 
 |_| |_|\___|\__,_|_|   \__,_|_|___/\__|_|\___|
                                               
         CLI-based Heuristic Malware Scanner (Go Edition)
`
	fmt.Printf("%s%s%s\n", ColorCyan, banner, ColorReset)
}

func GetScanPaths(scanAllDrives bool) ([]string, error) {
	if scanAllDrives {
		var drives []string
		if runtime.GOOS == "windows" {
			for i := 'A'; i <= 'Z'; i++ {
				drive := fmt.Sprintf("%c:\\", i)
				if _, err := os.Stat(drive); err == nil {
					drives = append(drives, drive)
				}
			}
			return drives, nil
		}

		// Linux & macOS drive detection
		f, err := os.Open("/proc/mounts")
		if err != nil {
			return []string{"/"}, nil
		}
		defer f.Close()

		seen := make(map[string]bool)
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 {
				continue
			}
			mountPoint := fields[1]
			if mountPoint == "/" || strings.HasPrefix(mountPoint, "/home") || strings.HasPrefix(mountPoint, "/mnt") || strings.HasPrefix(mountPoint, "/media") {
				if !seen[mountPoint] {
					seen[mountPoint] = true
					if _, err := os.Stat(mountPoint); err == nil {
						drives = append(drives, mountPoint)
					}
				}
			}
		}
		if err := sc.Err(); err != nil {
			fmt.Printf("%s[!] Error reading file: %v%s\n", ColorRed, err, ColorReset)
		}
		if len(drives) == 0 {
			return []string{"/"}, nil
		}
		return drives, nil
	}

	// GUI Folder Selection Logic
	var path string

	switch runtime.GOOS {
	case "windows":
		psCommand := `Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.FolderBrowserDialog; $f.Description = 'Select Folder to Scan'; if($f.ShowDialog() -eq 'OK') { $f.SelectedPath }`
		out, err := exec.Command("powershell", "-Command", psCommand).Output()
		if err != nil {
			return nil, fmt.Errorf("dialog closed or error: %v", err)
		}
		path = strings.TrimSpace(string(out))

	case "darwin":
		asCommand := `osascript -e 'set old_path to POSIX path of (choose folder with prompt "Select Folder to Scan")'`
		out, err := exec.Command("bash", "-c", asCommand).Output()
		if err != nil {
			return nil, fmt.Errorf("dialog closed or error: %v", err)
		}
		path = strings.TrimSpace(string(out))

	case "linux":
		// 1. Try zenity (GNOME / Default for many distros)
		if _, err := exec.LookPath("zenity"); err == nil {
			out, err := exec.Command("zenity", "--file-selection", "--directory", "--title=Select Folder to Scan").Output()
			if err != nil {
				return nil, fmt.Errorf("dialog closed or error")
			}
			path = strings.TrimSpace(string(out))

			// 2. Try kdialog (KDE / Kubuntu / Manjaro KDE)
		} else if _, err := exec.LookPath("kdialog"); err == nil {
			out, err := exec.Command("kdialog", "--getexistingdirectory", "/", "--title", "Select Folder to Scan").Output()
			if err != nil {
				return nil, fmt.Errorf("dialog closed or error")
			}
			path = strings.TrimSpace(string(out))

			// 3. Fallback to Command Line Input if no GUI tools are found
		} else {
			fmt.Printf("\n%s[!] GUI dialog tools (zenity/kdialog) are not installed.%s\n", ColorYellow, ColorReset)
			fmt.Print("Please enter the folder path to scan manually: ")
			reader := bufio.NewReader(os.Stdin)
			input, _ := reader.ReadString('\n')
			path = strings.TrimSpace(input)
		}

	default:
		return nil, fmt.Errorf("unsupported platform for GUI selection")
	}

	if path == "" {
		return nil, fmt.Errorf("no folder selected")
	}

	return []string{path}, nil
}

func interactiveMenu() {
	for {
		printBanner()
		fmt.Printf("  %s[1]%s Select folder via GUI Popup\n", ColorGreen, ColorReset)
		fmt.Printf("  %s[2]%s Specify directory path manually\n", ColorGreen, ColorReset)
		fmt.Printf("  %s[3]%s Scan entire system (All Drives)\n", ColorGreen, ColorReset)
		fmt.Printf("  %s[4]%s Import Signatures (File / VirusTotal)\n", ColorGreen, ColorReset)
		fmt.Printf("  %s[5]%s Change Threshold\n", ColorGreen, ColorReset)
		fmt.Printf("  %s[6]%s Configure Target Extensions\n", ColorGreen, ColorReset)
		statusColor := ColorRed
		statusText := "OFF"
		if SuppressCleanVT {
			statusColor = ColorGreen
			statusText = "ON"
		}
		fmt.Printf("  %s[7]%s Toggle Suppress Clean VT [Current: %s%s%s]\n", ColorGreen, ColorReset, statusColor, statusText, ColorReset)
		fmt.Printf("  %s[8]%s Clear Cache Database (cache.db)\n", ColorGreen, ColorReset)
		fmt.Printf("  %s[9]%s Exit Scanner\n", ColorGreen, ColorReset)
		fmt.Printf("\n%sPlease select an option (1-9) > %s", ColorYellow, ColorReset)

		var choice string
		fmt.Scanln(&choice)
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			fmt.Printf("%s[*] Waiting for folder selection from GUI popup...%s\n", ColorCyan, ColorReset)
			paths, err := GetScanPaths(false)
			if err != nil || len(paths) == 0 {
				fmt.Printf("%s[!] Canceled folder selection or dialog tool missing.%s\n", ColorRed, ColorReset)
			} else {
				fmt.Printf("%s[+] Selected folder: %s%s\n", ColorGreen, paths[0], ColorReset)
				ScanTargets(paths)
			}
		case "2":
			if runtime.GOOS == "windows" {
				fmt.Printf("%sEnter path to scan (e.g., C:\\Users) > %s", ColorYellow, ColorReset)
			} else {
				fmt.Printf("%sEnter path to scan (e.g., /home or /tmp) > %s", ColorYellow, ColorReset)
			}
			var path string
			fmt.Scanln(&path)
			path = strings.TrimSpace(strings.Trim(path, `"'`))
			if path != "" {
				ScanTargets([]string{path})
			} else {
				fmt.Printf("%s[!] Path cannot be empty.%s\n", ColorRed, ColorReset)
			}
		case "3":
			paths, err := GetScanPaths(true)
			if err != nil || len(paths) == 0 {
				fmt.Printf("%s[!] Error detecting drives: %v%s\n", ColorRed, err, ColorReset)
			} else {
				fmt.Printf("%s[*] Detected drives: %s%s\n", ColorCyan, strings.Join(paths, ", "), ColorReset)
				ScanTargets(paths)
			}
		case "4":
			fmt.Printf("\n%s=== Import Signatures ===%s\n", ColorCyan, ColorReset)
			fmt.Printf("  %s[a]%s Import from file (.json / .sql / .csv)\n", ColorGreen, ColorReset)
			fmt.Printf("  %s[b]%s Fetch ssdeep from VirusTotal (SHA256 / SHA1)\n", ColorGreen, ColorReset)
			fmt.Printf("\n%sSelect import method (a/b) > %s", ColorYellow, ColorReset)
			var subChoice string
			fmt.Scanln(&subChoice)
			switch strings.TrimSpace(strings.ToLower(subChoice)) {
			case "a":
				fmt.Printf("%sEnter path to .sql or .json import file > %s", ColorYellow, ColorReset)
				var path string
				fmt.Scanln(&path)
				path = strings.TrimSpace(strings.Trim(path, `"'`))
				if path != "" {
					importSigs(path)
				} else {
					fmt.Printf("%s[!] Path cannot be empty.%s\n", ColorRed, ColorReset)
				}
			case "b":
				fmt.Printf("%sEnter SHA256 or SHA1 hash > %s", ColorYellow, ColorReset)
				var hashInput string
				fmt.Scanln(&hashInput)
				hashInput = strings.TrimSpace(hashInput)
				if hashInput == "" {
					fmt.Printf("%s[!] Hash cannot be empty.%s\n", ColorRed, ColorReset)
					break
				}
				fmt.Printf("%sEnter malware name > %s", ColorYellow, ColorReset)
				var malName string
				fmt.Scanln(&malName)
				malName = strings.TrimSpace(malName)
				if malName == "" {
					fmt.Printf("%s[!] Malware name cannot be empty.%s\n", ColorRed, ColorReset)
					break
				}
				fmt.Printf("%s[*] Querying VirusTotal for: %s...%s\n", ColorCyan, hashInput, ColorReset)
				if err := FetchSsdeepFromVT(hashInput, malName); err != nil {
					fmt.Printf("%s[!] VT Import Error: %v%s\n", ColorRed, err, ColorReset)
				}
			default:
				fmt.Printf("%s[!] Invalid selection.%s\n", ColorRed, ColorReset)
			}
		case "5":
			var Thre string
			fmt.Print("Enter new Threshold score (0-100): ")
			fmt.Scanln(&Thre)
			Thre = strings.TrimSpace(strings.Trim(Thre, `"'`))

			if Thre != "" {
				convertedScore, err := strconv.Atoi(Thre)
				if err != nil {
					fmt.Printf("%s[!] Invalid number format. Please enter digits only.%s\n", ColorRed, ColorReset)
				} else if convertedScore < 0 || convertedScore > 100 {
					fmt.Printf("%s[!] Threshold must be between 0 and 100.%s\n", ColorRed, ColorReset)
				} else {
					Threshold = convertedScore
					fmt.Printf("[+] Successfully changed Threshold to: %d\n", Threshold)
				}
			} else {
				fmt.Printf("%s[!] Input cannot be empty.%s\n", ColorRed, ColorReset)
			}
		case "6":
			configureExtensions()
		case "7":
			SuppressCleanVT = !SuppressCleanVT
			status := "OFF"
			if SuppressCleanVT {
				status = "ON"
			}
			fmt.Printf("%s[+] Suppress Clean VT toggled to: %s%s\n", ColorGreen, status, ColorReset)
		case "8":
			clearCacheDB()
		case "9", "x", "X":
			fmt.Printf("%s[*] Exiting program...%s\n", ColorCyan, ColorReset)
			os.Exit(0)
		default:
			fmt.Printf("%s[!] Invalid selection, please try again.%s\n\n", ColorRed, ColorReset)
		}
	}
}

func main() {
	if err := LoadVTKeys(); err != nil {
		fmt.Printf("%s[!] Notice: Could not load vt_keys.txt: %v%s\n", ColorYellow, err, ColorReset)
	}

	LoadTrustedPublishers()

	// Normalize space-separated boolean flags (e.g., --suppress-vt false -> --suppress-vt=false)
	normalizedArgs := make([]string, 0, len(os.Args))
	for i := 0; i < len(os.Args); i++ {
		arg := os.Args[i]
		if (arg == "--suppress-vt" || arg == "-suppress-vt") && i+1 < len(os.Args) {
			nextVal := strings.ToLower(os.Args[i+1])
			if nextVal == "true" || nextVal == "false" || nextVal == "1" || nextVal == "0" {
				normalizedArgs = append(normalizedArgs, fmt.Sprintf("%s=%s", arg, nextVal))
				i++ // Skip next value argument
				continue
			}
		}
		normalizedArgs = append(normalizedArgs, arg)
	}
	os.Args = normalizedArgs

	// 1. Declare ALL Command-line flags
	importFile := flag.String("import", "", "Import .json, .sql, or .csv signatures file")
	threshInput := flag.Int("threshold", -1, "Set SSDEEP similarity threshold score (0-100)")
	configExt := flag.Bool("config-ext", false, "Configure target file extensions")
	suppressVTFlag := flag.Bool("suppress-vt", true, "Suppress VirusTotal clean results")
	clearCacheFlag := flag.Bool("clear-cache", false, "Delete cache database file (cache.db)")
	addSigFlag := flag.Bool("add-sig", false, "Add signature. Usage: --add-sig <malname> <hash>")
	vtImportFlag := flag.Bool("vt-import", false, "Import from VT. Usage: --vt-import <hash> <malname>")
	offlineFlag := flag.Bool("offline", false, "Disable VirusTotal and run completely offline")

	flag.Parse()

	// 2. Set Globals based on flags
	SuppressCleanVT = *suppressVTFlag
	OfflineMode = *offlineFlag

	if *threshInput != -1 {
		if *threshInput >= 0 && *threshInput <= 100 {
			Threshold = *threshInput
			fmt.Printf("%s[*] SSDEEP Threshold set to: %d%%%s\n", ColorCyan, Threshold, ColorReset)
		} else {
			fmt.Printf("%s[!] Invalid Threshold value (%d). Must be between 0 and 100.%s\n", ColorRed, *threshInput, ColorReset)
			os.Exit(1)
		}
	}

	// 3. Track if any utility action was run
	actionExecuted := false

	if *clearCacheFlag {
		clearCacheDB()
		actionExecuted = true
	}

	if *configExt {
		configureExtensions()
		actionExecuted = true
	}

	if *importFile != "" {
		importSigs(*importFile)
		actionExecuted = true
	}

	// 4. Handle Positional Arguments (Target Folders OR Signature text)
	args := flag.Args()

	if *addSigFlag {
		if len(args) < 2 {
			fmt.Printf("%s[!] Error: --add-sig requires exactly 2 arguments: <malname> <hash>%s\n", ColorRed, ColorReset)
			os.Exit(1)
		} else {
			addSig(args[0], args[1])
			actionExecuted = true
		}
	} else if *vtImportFlag {
		if len(args) < 2 {
			fmt.Printf("%s[!] Error: --vt-import requires exactly 2 arguments: <hash> <malname>%s\n", ColorRed, ColorReset)
			os.Exit(1)
		} else {
			fmt.Printf("%s[*] Querying VirusTotal for: %s...%s\n", ColorCyan, args[0], ColorReset)
			if err := FetchSsdeepFromVT(args[0], args[1]); err != nil {
				fmt.Printf("%s[!] VT Import Error: %v%s\n", ColorRed, err, ColorReset)
			}
			actionExecuted = true
		}
	} else if len(args) > 0 {
		printBanner()
		ScanTargets(args)
		actionExecuted = true
	}

	// 5. Final Routing
	if !actionExecuted {
		interactiveMenu()
	} else {
		fmt.Printf("\n%sPress Enter to exit...%s", ColorYellow, ColorReset)
		var wait string
		fmt.Scanln(&wait)
	}
}
