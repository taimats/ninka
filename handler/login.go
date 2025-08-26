package handler

import (
	"crypto/rand"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id := r.FormValue("id")
	secret := r.FormValue("secret")
	redirectTo := r.FormValue("redirect")
	if !isValidClient(id, secret, redirectTo) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	sessionId, err := generateRandomStr(rand.Reader, 16)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if err := sessionStore.Add(sessionId, id); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionId,
		Path:     "/",
		HttpOnly: true,
	})
	log.Printf("log in {userID: %s, sessionID: %s}\n", id, sessionId)
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func isValidClient(id, secret, redirectTo string) bool {
	cl, ok := clientStore.Data[id]
	if !ok {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(cl.Secret), []byte(secret))
	return err == nil && redirectTo == cl.RedirectTo
}
