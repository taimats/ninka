package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/taimats/ninka/handler"
	"github.com/taimats/ninka/middleware"
)

func main() {
	slog.SetDefault(slog.New(middleware.NewJSONIndentHandler(os.Stdout, nil)))

	mux := http.NewServeMux()
	mux.HandleFunc("/register", handler.RegisterHanlder)
	mux.HandleFunc("/login", handler.LoginHandler)
	mux.HandleFunc("/authorize", handler.AuthorizeHanler)
	mux.HandleFunc("/token", handler.TokenHandler)

	h := middleware.Use(mux, middleware.Logging)

	srv := &http.Server{
		Addr:        ":8080",
		Handler:     http.TimeoutHandler(h, time.Second, ""),
		ReadTimeout: 500 * time.Millisecond,
		IdleTimeout: time.Second,
	}
	go func() {
		log.Printf("server listening on port %s\n", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	<-ctx.Done()
	log.Println("Server shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("server forced to shut down: error: %s", err)
	}
	log.Println("server gracefully shut down!!")
}
