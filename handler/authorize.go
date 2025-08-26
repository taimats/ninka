package handler

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

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

func AuthorizeHanler(w http.ResponseWriter, r *http.Request) {
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
