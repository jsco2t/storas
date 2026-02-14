package compat

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"storas/test/integration"
)

func TestRcloneCompatibilitySuite(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("rclone"); err != nil {
		t.Skip("rclone binary not found in PATH")
	}
	env := integration.NewCompatEnv(t)

	work := t.TempDir()
	srcFile := filepath.Join(work, "src.txt")
	if err := os.WriteFile(srcFile, []byte("rclone-data"), 0o600); err != nil {
		t.Fatalf("write src file: %v", err)
	}
	multipartFile := filepath.Join(work, "multipart.txt")
	if err := os.WriteFile(multipartFile, []byte(strings.Repeat("x", 1024)), 0o600); err != nil {
		t.Fatalf("write multipart src file: %v", err)
	}

	rcloneCfg := filepath.Join(work, "rclone.conf")
	cfg := "[storas]\n" +
		"type = s3\n" +
		"provider = Other\n" +
		"env_auth = false\n" +
		"access_key_id = AKIAFULL\n" +
		"secret_access_key = secret-full\n" +
		"region = us-west-1\n" +
		"endpoint = " + env.BaseURL() + "\n" +
		"acl = private\n" +
		"force_path_style = true\n" +
		"no_check_bucket = true\n"
	if err := os.WriteFile(rcloneCfg, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write rclone config: %v", err)
	}

	env.MustReq(t, "PUT", "/rclone-bucket", nil, 200)

	runRclone(t, rcloneCfg, "--s3-acl", "private", "copyto", srcFile, "storas:rclone-bucket/file.txt")
	downloadedFile := filepath.Join(work, "downloaded.txt")
	runRclone(t, rcloneCfg, "copyto", "storas:rclone-bucket/file.txt", downloadedFile)
	downloaded, err := os.ReadFile(downloadedFile)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if strings.TrimSpace(string(downloaded)) != "rclone-data" {
		t.Fatalf("unexpected downloaded data: %q", string(downloaded))
	}
	runRclone(t, rcloneCfg, "deletefile", "storas:rclone-bucket/file.txt")

	runRclone(t, rcloneCfg, "--s3-acl", "private", "--s3-upload-cutoff", "0", "copyto", multipartFile, "storas:rclone-bucket/multipart.txt")
	downloadedMultipart := filepath.Join(work, "downloaded-multipart.txt")
	runRclone(t, rcloneCfg, "copyto", "storas:rclone-bucket/multipart.txt", downloadedMultipart)
	multipartDownloaded, err := os.ReadFile(downloadedMultipart)
	if err != nil {
		t.Fatalf("read multipart downloaded file: %v", err)
	}
	if strings.TrimSpace(string(multipartDownloaded)) == "" {
		t.Fatal("expected multipart uploaded data to be readable")
	}
	runRclone(t, rcloneCfg, "deletefile", "storas:rclone-bucket/multipart.txt")
}

func runRclone(t *testing.T, configPath string, args ...string) string {
	t.Helper()
	baseArgs := []string{"--config", configPath, "--s3-force-path-style=true"}
	cmd := exec.Command("rclone", append(baseArgs, args...)...)
	cmd.Env = append(os.Environ(), "RCLONE_S3_FORCE_PATH_STYLE=true")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("rclone %v failed: %v\n%s", args, err, out.String())
	}
	return out.String()
}
