package s3

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"storas/internal/config"
)

type contextKey string

const requestIDContextKey contextKey = "request_id"

type RouterConfig struct {
	ServiceHost string
	PathLive    string
	PathReady   string
	ReadyCheck  func() error
	Handler     func(http.ResponseWriter, *http.Request, RequestTarget, Operation)
	Logger      *slog.Logger
}

func NewRouter(cfg RouterConfig) http.Handler {
	mux := http.NewServeMux()
	livePath := cfg.PathLive
	if livePath == "" {
		livePath = config.DefaultHealthLive
	}
	readyPath := cfg.PathReady
	if readyPath == "" {
		readyPath = config.DefaultHealthReady
	}

	mux.HandleFunc(livePath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok")); err != nil {
			logWriteErr(cfg.Logger, "liveness", err)
		}
	})
	mux.HandleFunc(readyPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if cfg.ReadyCheck != nil {
			if err := cfg.ReadyCheck(); err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ready")); err != nil {
			logWriteErr(cfg.Logger, "readiness", err)
		}
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		target, err := ParseRequestTarget(r, cfg.ServiceHost)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		operation := ResolveOperation(r.Method, target, ParseDispatchQuery(r.URL.Query()), r.Header)
		if cfg.Handler == nil {
			w.WriteHeader(http.StatusNotImplemented)
			if _, err := w.Write([]byte(operation)); err != nil {
				logWriteErr(cfg.Logger, "unimplemented_operation", err)
			}
			return
		}
		cfg.Handler(w, r, target, operation)
	})

	return requestIDMiddleware(mux)
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := GenerateRequestID()
		ctx := context.WithValue(r.Context(), requestIDContextKey, reqID)
		w.Header().Set("X-Request-Id", reqID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GenerateRequestID() string {
	var entropy [8]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("req-%d-%s", time.Now().UnixNano(), hex.EncodeToString(entropy[:]))
}

func logWriteErr(logger *slog.Logger, endpoint string, err error) {
	if logger == nil {
		return
	}
	logger.Error("failed to write response body", "endpoint", endpoint, "error", err)
}

func RequestIDFromContext(ctx context.Context) string {
	if value, ok := ctx.Value(requestIDContextKey).(string); ok {
		return value
	}
	return ""
}
