package middleware

import (
	"bytes"
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

func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := bufpool.Get().(*bytes.Buffer)
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
			logger.LogAttrs(r.Context(), slog.LevelWarn, "client error",
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
