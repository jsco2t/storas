package s3

import "testing"

func TestIsValidBucketName(t *testing.T) {
	t.Parallel()
	valid := []string{
		"abc",
		"backup-01",
		"logs-prod",
		"logs.prod",
		"a.b-c.9",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 63 chars — max valid S3 bucket name length
	}
	for _, name := range valid {
		if !IsValidBucketName(name) {
			t.Fatalf("expected valid bucket: %s", name)
		}
	}

	invalid := []string{
		"",
		"ab",
		"UpperCase",
		"bad..dots",
		".startdot",
		"enddot.",
		"-start",
		"end-",
		"label.-dash",
		"label-.dash",
		"192.168.1.10",
		"has_underscore",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 64 chars — exceeds max S3 bucket name length
	}
	for _, name := range invalid {
		if IsValidBucketName(name) {
			t.Fatalf("expected invalid bucket: %s", name)
		}
	}
}
