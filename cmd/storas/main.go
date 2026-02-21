package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"storas/internal/api"
	"storas/internal/authz"
	"storas/internal/config"
	"storas/internal/logging"
	"storas/internal/runtime"
	"storas/internal/storage"
)

func main() {
	configPath := flag.String("config", "configs/config.yaml", "path to service config file")
	flag.Parse()

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		log.Printf("startup failed: %v", err)
		os.Exit(1)
	}

	logger := logging.New(cfg.Server.LogFormat, os.Stdout)

	authPermWarning, err := runtime.CheckAuthFilePermissions(cfg.Auth.AuthorizationFile)
	if err != nil {
		logger.Error("startup failed: authz file check", "error", err)
		os.Exit(1)
	}
	if authPermWarning != "" {
		logger.Warn("authorization file permissions warning", "warning", authPermWarning)
	}

	authEngine, err := authz.LoadFile(cfg.Auth.AuthorizationFile)
	if err != nil {
		logger.Error("startup failed: authz load", "error", err)
		os.Exit(1)
	}

	if err := runtime.EnsureStorageAvailable(cfg.Storage.DataDir); err != nil {
		logger.Error("startup failed: storage readiness", "error", err)
		os.Exit(1)
	}

	backend, err := storage.NewFSBackend(cfg.Storage.DataDir, cfg.Server.MaxBodyBytes)
	if err != nil {
		logger.Error("startup failed: storage backend", "error", err)
		os.Exit(1)
	}
	tmpDir := cfg.Storage.DataDir + "/tmp"
	if err := os.MkdirAll(tmpDir, 0o750); err != nil {
		logger.Error("startup failed: create temp dir", "error", err)
		os.Exit(1)
	}

	stopMultipartMaintenance := runMultipartMaintenance(context.Background(), logger, backend, cfg)
	stopLifecycleMaintenance := runLifecycleMaintenance(context.Background(), logger, backend, cfg)

	readyCheck := func() error {
		if authEngine == nil {
			return errReady("authz engine unavailable")
		}
		if err := runtime.EnsureStorageAvailable(cfg.Storage.DataDir); err != nil {
			return errReady(err.Error())
		}
		return nil
	}

	svc := &api.Service{
		Backend:           backend,
		Authz:             authEngine,
		Region:            cfg.Server.Region,
		ServiceName:       "s3",
		ClockSkew:         15 * time.Minute,
		ServiceHost:       hostFromListen(cfg.Server.ListenAddress),
		MaxBodyBytes:      cfg.Server.MaxBodyBytes,
		PathLive:          cfg.Health.PathLive,
		PathReady:         cfg.Health.PathReady,
		ReadyCheck:        readyCheck,
		Now:               time.Now,
		Logger:            logger,
		TrustProxyHeaders: cfg.Server.TrustProxyHeaders,
		TempDir:           tmpDir,
	}

	handler := withServerHeader(svc.Handler())

	srv, err := runtime.New(cfg, handler, logger)
	if err != nil {
		logger.Error("startup failed: server init", "error", err)
		os.Exit(1)
	}

	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-shutdownCh
		stopMultipartMaintenance()
		stopLifecycleMaintenance()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if shutdownErr := srv.Shutdown(ctx); shutdownErr != nil {
			logger.Error("graceful shutdown failed", "error", shutdownErr)
		}
	}()

	logger.Info("server starting", "addr", cfg.Server.ListenAddress, "tls_enabled", cfg.TLS.Enabled, "tls_mode", cfg.TLS.Mode)
	if err := srv.Start(); err != nil && err != http.ErrServerClosed {
		logger.Error("server exited with error", "error", err)
		os.Exit(1)
	}
	logger.Info("server stopped")
}

func hostFromListen(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			if i == 0 {
				return "localhost"
			}
			return addr[:i]
		}
	}
	return addr
}

func withServerHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "storas")
		next.ServeHTTP(w, r)
	})
}

type errReady string

func (e errReady) Error() string { return string(e) }

func runMultipartMaintenance(parent context.Context, logger *slog.Logger, backend *storage.FSBackend, cfg config.Config) func() {
	mcfg := cfg.Storage.MultipartMaintenance
	if !mcfg.Enabled {
		return func() {}
	}
	if backend == nil {
		logger.Warn("multipart maintenance enabled but backend is nil; maintenance worker disabled")
		return func() {}
	}

	staleAfter := time.Duration(mcfg.StaleAfterSeconds) * time.Second
	sweepOpts := storage.MultipartSweepOptions{
		StaleAfter:            staleAfter,
		MaxRemovals:           mcfg.MaxRemovalsPerSweep,
		RemoveCorruptUploads:  mcfg.RemoveCorruptUploads,
		CleanupTemporaryFiles: mcfg.CleanupTemporaryFiles,
		TempFileStaleAfter:    time.Duration(mcfg.TempFileStaleAfterSeconds) * time.Second,
	}
	if mcfg.StartupSweep {
		res, err := backend.SweepStaleMultipartUploads(parent, time.Now().UTC(), sweepOpts)
		if err != nil {
			logger.Warn("multipart startup sweep completed with errors",
				"error", err,
				"buckets_scanned", res.BucketsScanned,
				"uploads_scanned", res.UploadsScanned,
				"uploads_removed", res.UploadsRemoved,
				"corrupted_uploads_found", res.CorruptedUploadsFound,
				"corrupted_uploads_kept", res.CorruptedUploadsKept,
				"temp_files_removed", res.TempFilesRemoved,
				"skipped_by_removal_limit", res.SkippedByRemovalLimit,
			)
		} else {
			logger.Info("multipart startup sweep completed",
				"buckets_scanned", res.BucketsScanned,
				"uploads_scanned", res.UploadsScanned,
				"uploads_removed", res.UploadsRemoved,
				"corrupted_uploads_found", res.CorruptedUploadsFound,
				"corrupted_uploads_kept", res.CorruptedUploadsKept,
				"temp_files_removed", res.TempFilesRemoved,
				"skipped_by_removal_limit", res.SkippedByRemovalLimit,
			)
		}
	}

	ctx, cancel := context.WithCancel(parent)
	interval := time.Duration(mcfg.SweepIntervalSeconds) * time.Second
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case t := <-ticker.C:
				res, err := backend.SweepStaleMultipartUploads(ctx, t.UTC(), sweepOpts)
				if err != nil {
					logger.Warn("multipart periodic sweep completed with errors",
						"error", err,
						"buckets_scanned", res.BucketsScanned,
						"uploads_scanned", res.UploadsScanned,
						"uploads_removed", res.UploadsRemoved,
						"corrupted_uploads_found", res.CorruptedUploadsFound,
						"corrupted_uploads_kept", res.CorruptedUploadsKept,
						"temp_files_removed", res.TempFilesRemoved,
						"skipped_by_removal_limit", res.SkippedByRemovalLimit,
					)
					continue
				}
				logger.Info("multipart periodic sweep completed",
					"buckets_scanned", res.BucketsScanned,
					"uploads_scanned", res.UploadsScanned,
					"uploads_removed", res.UploadsRemoved,
					"corrupted_uploads_found", res.CorruptedUploadsFound,
					"corrupted_uploads_kept", res.CorruptedUploadsKept,
					"temp_files_removed", res.TempFilesRemoved,
					"skipped_by_removal_limit", res.SkippedByRemovalLimit,
				)
			}
		}
	}()

	return cancel
}

func runLifecycleMaintenance(parent context.Context, logger *slog.Logger, backend *storage.FSBackend, cfg config.Config) func() {
	lcfg := cfg.Storage.LifecycleMaintenance
	if !lcfg.Enabled {
		return func() {}
	}
	if backend == nil {
		logger.Warn("lifecycle maintenance enabled but backend is nil; maintenance worker disabled")
		return func() {}
	}

	sweepOpts := storage.LifecycleSweepOptions{
		MaxActions: lcfg.MaxActionsPerSweep,
		DryRun:     lcfg.DryRun,
	}
	if lcfg.StartupSweep {
		res, err := backend.SweepLifecycle(parent, time.Now().UTC(), sweepOpts)
		logLifecycleSweep(logger, "lifecycle startup sweep", res, err)
	}

	ctx, cancel := context.WithCancel(parent)
	interval := time.Duration(lcfg.SweepIntervalSeconds) * time.Second
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case t := <-ticker.C:
				res, err := backend.SweepLifecycle(ctx, t.UTC(), sweepOpts)
				logLifecycleSweep(logger, "lifecycle periodic sweep", res, err)
			}
		}
	}()
	return cancel
}

func logLifecycleSweep(logger *slog.Logger, msg string, res storage.LifecycleMaintenanceResult, err error) {
	matchedTotal := 0
	appliedTotal := 0
	skippedTotal := 0
	actionBreakdown := map[string]int{}
	for _, rr := range res.RuleResults {
		matchedTotal += rr.MatchedCandidates
		appliedTotal += rr.AppliedActions
		skippedTotal += rr.SkippedByLimit
		actionBreakdown[rr.Action] += rr.AppliedActions
	}
	base := []any{
		"buckets_scanned", res.BucketsScanned,
		"rules_evaluated", res.RulesEvaluated,
		"actions_executed", res.ActionsExecuted,
		"actions_dry_run", res.ActionsDryRun,
		"skipped_by_limit", res.SkippedByLimit,
		"matched_candidates_total", matchedTotal,
		"applied_actions_total", appliedTotal,
		"rule_skipped_by_limit_total", skippedTotal,
		"applied_expire_current", actionBreakdown["expire-current"],
		"applied_expire_noncurrent", actionBreakdown["expire-noncurrent"],
		"applied_abort_multipart", actionBreakdown["abort-multipart"],
		"rule_result_count", len(res.RuleResults),
	}
	for _, rr := range res.RuleResults {
		levelMsg := msg + " rule result"
		fields := make([]any, 0, 12)
		fields = append(fields,
			"bucket", rr.Bucket,
			"rule_id", rr.RuleID,
			"action", rr.Action,
			"matched_candidates", rr.MatchedCandidates,
			"applied_actions", rr.AppliedActions,
			"skipped_by_limit", rr.SkippedByLimit,
		)
		if err != nil {
			logger.Warn(levelMsg, append(fields, "error", err)...)
			continue
		}
		logger.Info(levelMsg, fields...)
	}
	if err != nil {
		logger.Warn(msg+" completed with errors", append(base, "error", err)...)
		return
	}
	logger.Info(msg+" completed", base...)
}
