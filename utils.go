package minioth

import (
	"regexp"
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
	re := regexp.MustCompile(`^[a-zA-Z0-9@]+$`)
	return re.MatchString(s)
}

func IsValidUTF8String(s string) bool {
	// Updated regex to include space (\s) and new line (\n) characters
	re := regexp.MustCompile(`^[\p{L}\p{N}\s\n!@#\$%\^&\*\(\):\?><\.\-]+$`)

	return re.MatchString(s)
}
