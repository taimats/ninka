package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
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
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	<-quit
	log.Println("Server shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("server forced to shut down: error: %s", err)
	}
	log.Println("server gracefully shut down!!")
}
