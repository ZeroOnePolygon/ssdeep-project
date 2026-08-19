//go:build windows

package main

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ──────────────────────────────────────────────
// Windows API declarations
// ──────────────────────────────────────────────

var (
	modWintrust = windows.NewLazySystemDLL("wintrust.dll")
	modVersion  = windows.NewLazySystemDLL("version.dll")

	procWinVerifyTrust          = modWintrust.NewProc("WinVerifyTrust")
	procGetFileVersionInfoSizeW = modVersion.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfoW     = modVersion.NewProc("GetFileVersionInfoW")
	procVerQueryValueW          = modVersion.NewProc("VerQueryValueW")
)

// WinVerifyTrust constants [Optimized]
const (
	wtdUIChoiceNone          = 2
	wtdRevokeNone            = 0
	wtdChoiceFile            = 1
	wtdStateActionIgnore     = 0
	wtdStateActionVerify     = 1          // [ADD] Verify and build the trust chain
	wtdStateActionClose      = 2          // [ADD] Free the memory allocated by Verify
	wtdCacheOnlyUrlRetrieval = 0x00001000 // [ADD] Prevent network delays/hangs (Offline mode)

	trustENoSignature       = uintptr(0x800B0100)
	trustEExplicitDistrust  = uintptr(0x800B0111)
	trustESubjectNotTrusted = uintptr(0x800B0004)
)

// WINTRUST_FILE_INFO layout (64-bit compatible)
type wtFileInfo struct {
	cbStruct      uint32
	_pad0         [4]byte
	pcwszFilePath uintptr
	hFile         uintptr
	pgKnownSubj   uintptr
}

// WINTRUST_DATA layout (64-bit compatible)
type wtData struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	pUnion              uintptr
	dwStateAction       uint32
	hWVTStateData       uintptr
	pwszURLReference    uintptr
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  uintptr
}

// actionGenericVerifyV2 is the GUID for generic file Authenticode verification
var actionGenericVerifyV2 = windows.GUID{
	Data1: 0x00AAC56B,
	Data2: 0xCD44,
	Data3: 0x11D0,
	Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
}

// hasValidAuthenticode returns true if the file has a valid Authenticode signature.
// [Optimized]: Prevents memory leaks and network hang during bulk scanning.
func hasValidAuthenticode(filePath string) bool {
	path16, err := windows.UTF16PtrFromString(filePath)
	if err != nil {
		return false
	}

	fi := wtFileInfo{
		cbStruct:      uint32(unsafe.Sizeof(wtFileInfo{})),
		pcwszFilePath: uintptr(unsafe.Pointer(path16)),
		hFile:         0,
		pgKnownSubj:   0,
	}

	wd := wtData{
		cbStruct:            uint32(unsafe.Sizeof(wtData{})),
		pPolicyCallbackData: 0,
		pSIPClientData:      0,
		dwUIChoice:          wtdUIChoiceNone,
		fdwRevocationChecks: wtdRevokeNone,
		dwUnionChoice:       wtdChoiceFile,
		pUnion:              uintptr(unsafe.Pointer(&fi)),
		dwStateAction:       wtdStateActionVerify,     // [Fix] Build state properly
		dwProvFlags:         wtdCacheOnlyUrlRetrieval, // [Fix] No network calls (Speed boost)
	}

	invalidHandle := uintptr(windows.InvalidHandle)

	// Step 1: Verify the signature and build the state
	ret, _, _ := procWinVerifyTrust.Call(
		invalidHandle,
		uintptr(unsafe.Pointer(&actionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&wd)),
	)

	// Step 2: FREE THE MEMORY (Crucial for Scanners)
	// If we don't do this, WinVerifyTrust leaks memory handles for every file scanned.
	wd.dwStateAction = wtdStateActionClose
	procWinVerifyTrust.Call(
		invalidHandle,
		uintptr(unsafe.Pointer(&actionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&wd)),
	)

	// 0 = valid embedded signature
	return ret == 0
}

// getPECompanyName reads the CompanyName string from a PE file's version resource.
// [Optimized]: Added broader language fallback for accurate malware unmasking.
func getPECompanyName(filePath string) (string, error) {
	path16, err := windows.UTF16PtrFromString(filePath)
	if err != nil {
		return "", err
	}

	// Step 1: Get required buffer size
	size, _, _ := procGetFileVersionInfoSizeW.Call(
		uintptr(unsafe.Pointer(path16)),
		0,
	)
	if size == 0 {
		return "", fmt.Errorf("no version info")
	}

	// Step 2: Read version info into buffer
	buf := make([]byte, size)
	ret, _, _ := procGetFileVersionInfoW.Call(
		uintptr(unsafe.Pointer(path16)),
		0,
		size,
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if ret == 0 {
		return "", fmt.Errorf("GetFileVersionInfoW failed")
	}

	// Step 3: Get translation table (\VarFileInfo\Translation)
	transQuery, _ := windows.UTF16PtrFromString(`\VarFileInfo\Translation`)
	var transPtr unsafe.Pointer
	var transLen uint32
	ret, _, _ = procVerQueryValueW.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(transQuery)),
		uintptr(unsafe.Pointer(&transPtr)),
		uintptr(unsafe.Pointer(&transLen)),
	)

	// Build list of lang+codepage strings to query
	var langCPs []string
	if ret != 0 && transLen >= 4 {
		numTrans := transLen / 4
		for i := uint32(0); i < numTrans; i++ {
			langPtr := (*uint16)(unsafe.Pointer(uintptr(transPtr) + uintptr(i*4)))
			cpPtr := (*uint16)(unsafe.Pointer(uintptr(transPtr) + uintptr(i*4+2)))

			lang := *langPtr
			cp := *cpPtr
			langCPs = append(langCPs, fmt.Sprintf(`\StringFileInfo\%04x%04x\CompanyName`, lang, cp))
		}
	}

	// Fallbacks
	langCPs = append(langCPs,
		`\StringFileInfo\040904B0\CompanyName`, // English, Unicode
		`\StringFileInfo\040904E4\CompanyName`, // English, Windows Multilingual
		`\StringFileInfo\04090000\CompanyName`, // English, Neutral Codepage
		`\StringFileInfo\000004B0\CompanyName`, // Language neutral, Unicode
		`\StringFileInfo\00000000\CompanyName`, // Unknown Language, Neutral Codepage
	)

	// Step 4: Query CompanyName for each lang/codepage
	for _, query := range langCPs {
		q16, _ := windows.UTF16PtrFromString(query)
		var valPtr unsafe.Pointer
		var valLen uint32
		ret, _, _ = procVerQueryValueW.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(q16)),
			uintptr(unsafe.Pointer(&valPtr)),
			uintptr(unsafe.Pointer(&valLen)),
		)
		if ret != 0 && valLen > 0 && valPtr != nil {
			company := windows.UTF16PtrToString((*uint16)(valPtr))
			company = strings.TrimSpace(strings.Trim(company, "\x00"))
			if company != "" {
				return company, nil
			}
		}
	}

	return "", fmt.Errorf("CompanyName not found")
}
