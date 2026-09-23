package util

import (
	"regexp"
	"strings"
)

// Security related utils
func IsNumeric(s string) bool {
	re := regexp.MustCompile(`^[0-9]+$`)
	return re.MatchString(s)
}

func IsAlphanumeric(s string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	return re.MatchString(s)
}

func IsAlphanumericPlus(s string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9@_]+$`)
	return re.MatchString(s)
}

func IsValidUTF8String(s string) bool {
	// Updated regex to include space (\s) and new line (\n) characters
	re := regexp.MustCompile(`^[\p{L}\p{N}\s\n!@#\$%\^&\*\(\):\?><\.\-]+$`)

	return re.MatchString(s)
}

// IsValidEmail is a lightweight, not-fully-RFC5322 format check — good
// enough to catch typos and garbage input, not meant to verify
// deliverability (that's what the email-verification flow is for).
func IsValidEmail(s string) bool {
	re := regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	return re.MatchString(s)
}

// SplitSelectID parses the ad-hoc "resource?key=value" syntax used by
// MiniothHandler.Select (e.g. "users?uid=1000"), shared by every handler
// implementation instead of each one re-parsing it its own way.
func SplitSelectID(id string) (base, param, value string) {
	parts := strings.SplitN(id, "?", 2)
	base = parts[0]
	if len(parts) != 2 {
		return base, "", ""
	}
	kv := strings.SplitN(parts[1], "=", 2)
	if len(kv) != 2 {
		return base, "", ""
	}
	return base, kv[0], kv[1]
}
