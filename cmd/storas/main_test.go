package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"storas/internal/config"
	"storas/internal/storage"
)

func TestRunMultipartMaintenanceStartupSweepRemovesStaleUpload(t *testing.T) {
	t.Parallel()
	backend, err := storage.NewFSBackend(t.TempDir(), 1024*1024)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	if err := backend.CreateBucket(context.Background(), "maint-bucket"); err != nil {
		t.Fatalf("CreateBucket error: %v", err)
	}

	uploadID, err := backend.CreateMultipartUpload(context.Background(), "maint-bucket", "obj.txt", storage.ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload error: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)

	cfg := config.Default()
	cfg.Storage.MultipartMaintenance.Enabled = true
	cfg.Storage.MultipartMaintenance.StartupSweep = true
	cfg.Storage.MultipartMaintenance.SweepIntervalSeconds = 3600
	cfg.Storage.MultipartMaintenance.StaleAfterSeconds = 1

	stop := runMultipartMaintenance(context.Background(), slog.New(slog.NewTextHandler(os.Stdout, nil)), backend, cfg)
	defer stop()

	_, err = backend.ListParts(context.Background(), "maint-bucket", "obj.txt", uploadID, storage.ListPartsOptions{})
	if !errors.Is(err, storage.ErrNoSuchUpload) {
		t.Fatalf("expected stale upload removed by startup sweep, got %v", err)
	}
}

func TestRunMultipartMaintenanceDisabledNoop(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Storage.MultipartMaintenance.Enabled = false

	stop := runMultipartMaintenance(context.Background(), slog.New(slog.NewTextHandler(os.Stdout, nil)), nil, cfg)
	stop()
}

func TestRunMultipartMaintenanceEnabledWithNilBackendNoop(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Storage.MultipartMaintenance.Enabled = true

	stop := runMultipartMaintenance(context.Background(), slog.New(slog.NewTextHandler(os.Stdout, nil)), nil, cfg)
	stop()
}
