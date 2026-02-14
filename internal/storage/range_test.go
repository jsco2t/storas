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
	invalid := []string{"", "chars=0-1", "bytes=1-0", "bytes=100-200", "bytes=1-2,3-4"}
	for _, value := range invalid {
		if value == "" {
			continue
		}
		if _, _, err := ParseRange(value, 100); err == nil {
			t.Fatalf("expected invalid range error for %q", value)
		}
	}
}
