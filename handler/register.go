package handler

import (
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

type Password string

func (p Password) String() string {
	return "********"
}
func (p Password) GoString() string {
	return "********"
}

type Client struct {
	ID         string   `json:"id"`
	Secret     Password `json:"secret"`
	RedirectTo string   `json:"redirect_to"`
}

func NewClient(id string, secret Password, redirectTo string) *Client {
	return &Client{
		ID:         id,
		Secret:     secret,
		RedirectTo: redirectTo,
	}
}

func RegisterHanlder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_, _, ok := r.BasicAuth()
	if ok {
		http.Error(w, "not allow basic auth", http.StatusUnauthorized)
		return
	}

	var cl Client
	err := json.NewEncoder(w).Encode(&cl)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if cl.ID == "" || cl.Secret == "" || cl.RedirectTo == "" {
		http.Error(w, "body should not be empty", http.StatusBadRequest)
		return
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(cl.Secret), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	cl.Secret = Password(hashedPass)

	if err := clientStore.Add(cl.ID, &cl); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
