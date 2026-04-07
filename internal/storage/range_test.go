package storage

import "testing"

func TestParseRangeValidForms(t *testing.T) {
	t.Parallel()
	start, end, err := ParseRange("bytes=10-19", 100)
	if err != nil || start != 10 || end != 19 {
		t.Fatalf("unexpected explicit range: %d-%d err=%v", start, end, err)
	}

	start, end, err = ParseRange("bytes=10-", 100)
	if err != nil || start != 10 || end != 99 {
		t.Fatalf("unexpected open-ended range: %d-%d err=%v", start, end, err)
	}

	start, end, err = ParseRange("bytes=-5", 100)
	if err != nil || start != 95 || end != 99 {
		t.Fatalf("unexpected suffix range: %d-%d err=%v", start, end, err)
	}
}

func TestParseRangeInvalidForms(t *testing.T) {
	t.Parallel()
	// Empty string is a valid range (means full object) — it is intentionally absent here.
	invalid := []string{"chars=0-1", "bytes=1-0", "bytes=100-200", "bytes=1-2,3-4"}
	for _, value := range invalid {
		if _, _, err := ParseRange(value, 100); err == nil {
			t.Fatalf("expected invalid range error for %q", value)
		}
	}
}

func TestParseRangeEmptyStringReturnsFullRange(t *testing.T) {
	t.Parallel()
	start, end, err := ParseRange("", 100)
	if err != nil || start != 0 || end != 99 {
		t.Fatalf("empty range should return full object: got start=%d end=%d err=%v", start, end, err)
	}
}

func TestParseRangeSuffixClampedToSize(t *testing.T) {
	t.Parallel()
	start, end, err := ParseRange("bytes=-200", 100)
	if err != nil || start != 0 || end != 99 {
		t.Fatalf("suffix range exceeding size should clamp to full object: got start=%d end=%d err=%v", start, end, err)
	}
}
