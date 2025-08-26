package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var clientStore = NewStore[string, *Client]("client")
var sessionStore = NewStore[string, string]("session")
var authcodeStore = NewStore[string, AuthCode]("authcode")

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

type AuthRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	State               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
}

func NewAuthRequest(r *http.Request) *AuthRequest {
	return &AuthRequest{
		ResponseType:        r.URL.Query().Get("response_type"),
		ClientID:            r.URL.Query().Get("client_id"),
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		State:               r.URL.Query().Get("state"),
		Scope:               r.URL.Query().Get("scope"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
		Nonce:               r.URL.Query().Get("nonce"),
	}
}

func (ar *AuthRequest) Validate() (errMsg string, statusCode int) {
	if ar.ResponseType != "code" {
		return "unsupported response type", http.StatusBadRequest
	}
	if !clientStore.exists(ar.ClientID) {
		return "invalid client id", http.StatusBadRequest
	}
	cl := clientStore.Data[ar.ClientID]
	if ar.RedirectURI == "" || ar.RedirectURI != cl.RedirectTo {
		return "invalid redirect uri", http.StatusBadRequest
	}
	if ar.CodeChallengeMethod == "" {
		ar.CodeChallengeMethod = "plain"
	}
	if ar.CodeChallengeMethod != "S256" && ar.CodeChallengeMethod != "plain" {
		return "unsupported code challenge method", http.StatusBadRequest
	}
	return "", 0
}

type AuthCode struct {
	ClientID            string
	UserID              string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	Scope               string
	ExpireAt            time.Time
}

func NewAuthCode(ar *AuthRequest, userId string) AuthCode {
	return AuthCode{
		ClientID:            ar.ClientID,
		UserID:              userId,
		RedirectURI:         ar.RedirectURI,
		CodeChallenge:       ar.CodeChallenge,
		CodeChallengeMethod: ar.CodeChallengeMethod,
		Nonce:               ar.Nonce,
		Scope:               ar.Scope,
		ExpireAt:            time.Now().Add(5 * time.Minute),
	}
}

func registerHanlder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_, _, ok := r.BasicAuth()
	if ok {
		http.Error(w, "not allow basic auth", http.StatusUnauthorized)
		return
	}

	var cl *Client
	err := json.NewEncoder(w).Encode(cl)
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

	if err := clientStore.Add(cl.ID, cl); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
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

func authorizeHanler(w http.ResponseWriter, r *http.Request) {
	var userId string
	if c, err := r.Cookie("session_id"); err == nil {
		v, ok := sessionStore.Data[c.Value]
		if ok {
			userId = v
		}
	}
	if userId == "" {
		redirectURL := "/login?redirect=" + url.QueryEscape(r.RequestURI)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	ar := NewAuthRequest(r)
	msg, statusCode := ar.Validate()
	if msg != "" {
		http.Error(w, msg, statusCode)
		return
	}
	code, err := generateRandomStr(rand.Reader, 32)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	authcodeStore.Data[code] = NewAuthCode(ar, userId)

	v := url.Values{}
	v.Add("code", url.QueryEscape(code))
	if ar.State != "" {
		v.Add("state", url.QueryEscape(ar.State))
	}
	redirectTo := fmt.Sprintf("%s?%s", ar.RedirectURI, v.Encode())
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

// The returned string is url-safe because the generated random data is based64-encoded under the hood.
func generateRandomStr(r io.Reader, size int) (string, error) {
	b := make([]byte, size)
	if _, err := r.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
