package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
)

var bufpool = &sync.Pool{
	New: func() any {
		return &bytes.Buffer{}
	},
}

type JSONIndentHandler struct {
	h   slog.Handler
	out io.Writer //out from logging
	mu  *sync.Mutex
	buf *bytes.Buffer
}

var _ slog.Handler = (*JSONIndentHandler)(nil)

func NewJSONIndentHandler(out io.Writer, opts *slog.HandlerOptions) *JSONIndentHandler {
	var buf bytes.Buffer
	return &JSONIndentHandler{
		h:   slog.NewJSONHandler(&buf, opts),
		out: out,
		mu:  &sync.Mutex{},
		buf: &buf,
	}
}

func (i *JSONIndentHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return i.h.Enabled(ctx, level)
}

func (i *JSONIndentHandler) Handle(ctx context.Context, record slog.Record) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if err := i.h.Handle(ctx, record); err != nil {
		return err
	}

	encoder := json.NewEncoder(i.out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(json.RawMessage(i.buf.Bytes())); err != nil {
		return fmt.Errorf("failed to Encode in the JSON format: %w", err)
	}
	i.buf.Reset()
	return nil
}

func (i *JSONIndentHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &JSONIndentHandler{
		h:   i.h.WithAttrs(attrs),
		out: i.out,
		mu:  i.mu,
		buf: i.buf,
	}
}

func (i *JSONIndentHandler) WithGroup(name string) slog.Handler {
	return &JSONIndentHandler{
		h:   i.h.WithGroup(name),
		out: i.out,
		mu:  i.mu,
		buf: i.buf,
	}
}

func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := bufpool.Get().(*bytes.Buffer)
		defer buf.Reset()
		defer bufpool.Put(buf)

		ww := newWrappedWriter(w, buf)

		next.ServeHTTP(ww, r)

		statusCode := ww.statusCode
		errMsg := strings.TrimSuffix(buf.String(), "\n")
		logger := slog.With(
			slog.String("remote_address", r.RemoteAddr),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", statusCode),
		)
		if 200 <= statusCode && statusCode < 400 {
			logger.LogAttrs(r.Context(), slog.LevelInfo, "OK")
		}
		if 400 <= statusCode && statusCode < 500 {
			logger.LogAttrs(r.Context(), slog.LevelError, "client error",
				slog.String("error", errMsg),
			)
		}
		if 500 <= statusCode && statusCode < 600 {
			logger.LogAttrs(r.Context(), slog.LevelWarn, "server error",
				slog.String("error", errMsg),
			)
		}
	})
}

type wrappedWriter struct {
	w          http.ResponseWriter
	mw         io.Writer //multiWriter
	statusCode int
}

func newWrappedWriter(w http.ResponseWriter, buf io.Writer) *wrappedWriter {
	return &wrappedWriter{
		w:  w,
		mw: io.MultiWriter(w, buf),
	}
}

func (ww *wrappedWriter) Header() http.Header {
	return ww.w.Header()
}

func (ww *wrappedWriter) Write(p []byte) (int, error) {
	return ww.mw.Write(p)
}

func (ww *wrappedWriter) WriteHeader(statusCode int) {
	ww.statusCode = statusCode
	ww.w.WriteHeader(statusCode)
}
