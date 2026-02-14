package s3

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

type contextKey string

const requestIDContextKey contextKey = "request_id"

type RouterConfig struct {
	ServiceHost string
	PathLive    string
	PathReady   string
	ReadyCheck  func() error
	Handler     func(http.ResponseWriter, *http.Request, RequestTarget, Operation)
}

func NewRouter(cfg RouterConfig) http.Handler {
	mux := http.NewServeMux()
	livePath := cfg.PathLive
	if livePath == "" {
		livePath = "/healthz"
	}
	readyPath := cfg.PathReady
	if readyPath == "" {
		readyPath = "/readyz"
	}

	mux.HandleFunc(livePath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
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
		_, _ = w.Write([]byte("ready"))
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
			_, _ = w.Write([]byte(operation))
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

func RequestIDFromContext(ctx context.Context) string {
	if value, ok := ctx.Value(requestIDContextKey).(string); ok {
		return value
	}
	return ""
}
