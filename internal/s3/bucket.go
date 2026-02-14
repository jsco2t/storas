package s3

import (
	"net"
	"strings"
)

func IsValidBucketName(name string) bool {
	if len(name) < 3 || len(name) > 63 {
		return false
	}
	if strings.Contains(name, "..") || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return false
	}
	for _, r := range name {
		isDigit := r >= '0' && r <= '9'
		isLower := r >= 'a' && r <= 'z'
		if !(isDigit || isLower || r == '-' || r == '.') {
			return false
		}
	}
	if net.ParseIP(name) != nil {
		return false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if label == "" {
			return false
		}
		for i, r := range label {
			isDigit := r >= '0' && r <= '9'
			isLower := r >= 'a' && r <= 'z'
			if !(isDigit || isLower || r == '-') {
				return false
			}
			if (i == 0 || i == len(label)-1) && r == '-' {
				return false
			}
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}
