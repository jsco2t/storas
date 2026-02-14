package runtime

import (
	"fmt"
	"os"
	"path/filepath"
)

func CheckAuthFilePermissions(path string) (string, error) {
	clean := filepath.Clean(path)
	info, err := os.Stat(clean)
	if err != nil {
		return "", fmt.Errorf("stat auth file: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("auth file path %q is a directory", clean)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Sprintf("authorization file %q has overly broad permissions %o; recommended mode is 0600", clean, info.Mode().Perm()), nil
	}
	return "", nil
}
