package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/taimats/ninka/handler"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/register", handler.RegisterHanlder)
	mux.HandleFunc("/login", handler.LoginHandler)
	mux.HandleFunc("/authorize", handler.AuthorizeHanler)
	mux.HandleFunc("/token", handler.TokenHandler)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
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
