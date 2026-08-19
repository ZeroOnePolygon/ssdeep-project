//go:build !windows

package main

// hasValidAuthenticode is not supported on non-Windows platforms.
// Always returns false so the scanner falls through to CompanyName check.
func hasValidAuthenticode(_ string) bool {
	return false
}

// getPECompanyName is not implemented on non-Windows platforms.
func getPECompanyName(_ string) (string, error) {
	return "", nil
}
