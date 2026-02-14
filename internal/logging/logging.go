package logging

import (
	"io"
	"log/slog"
	"os"
)

func New(format string, w io.Writer) *slog.Logger {
	if w == nil {
		w = os.Stdout
	}
	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})
	} else {
		handler = slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	return slog.New(handler)
}
