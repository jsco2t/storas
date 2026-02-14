package storage

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseRange parses a single HTTP byte range and returns an inclusive [start,end].
func ParseRange(value string, size int64) (int64, int64, error) {
	if size < 0 {
		return 0, 0, ErrInvalidRange
	}
	if value == "" {
		return 0, size - 1, nil
	}
	if !strings.HasPrefix(value, "bytes=") {
		return 0, 0, ErrInvalidRange
	}

	spec := strings.TrimPrefix(value, "bytes=")
	if strings.Contains(spec, ",") {
		return 0, 0, ErrInvalidRange
	}
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return 0, 0, ErrInvalidRange
	}

	startStr := strings.TrimSpace(parts[0])
	endStr := strings.TrimSpace(parts[1])

	if startStr == "" {
		suffixLen, err := strconv.ParseInt(endStr, 10, 64)
		if err != nil || suffixLen <= 0 {
			return 0, 0, ErrInvalidRange
		}
		if suffixLen >= size {
			return 0, size - 1, nil
		}
		return size - suffixLen, size - 1, nil
	}

	start, err := strconv.ParseInt(startStr, 10, 64)
	if err != nil || start < 0 || start >= size {
		return 0, 0, ErrInvalidRange
	}

	if endStr == "" {
		return start, size - 1, nil
	}

	end, err := strconv.ParseInt(endStr, 10, 64)
	if err != nil || end < start {
		return 0, 0, ErrInvalidRange
	}
	if end >= size {
		end = size - 1
	}

	return start, end, nil
}

func contentRange(start, end, size int64) string {
	return fmt.Sprintf("bytes %d-%d/%d", start, end, size)
}
