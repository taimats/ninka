package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	contentTypeJSON       = "application/json"
	contentTypeUrlEncoded = "application/x-www-form-urlencoded"
)

var jwtSignedKey = os.Getenv("JWT_SIGNED_KEY")

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	CodeVerifier string `json:"code_verifier"`
}

func NewTokenRequest(contentType string, r *http.Request) *TokenRequest {
	switch contentType {
	case contentTypeUrlEncoded:
		return &TokenRequest{
			GrantType:    r.URL.Query().Get("grant_type"),
			ClientID:     r.URL.Query().Get("client_id"),
			ClientSecret: r.URL.Query().Get("client_secret"),
			Code:         r.URL.Query().Get("code"),
			RedirectURI:  r.URL.Query().Get("redirect_uri"),
			CodeVerifier: r.URL.Query().Get("code_verifier"),
		}
	case contentTypeJSON:
		var tr TokenRequest
		err := json.NewDecoder(r.Body).Decode(&tr)
		if err != nil {
			return nil
		}
		return &tr
	default:
		return nil
	}
}

func (tr *TokenRequest) Validate() (authcode AuthCode, errMsg string, statusCode int) {
	if tr.GrantType != "authorization_code" {
		return AuthCode{}, "unsupported grant type", http.StatusBadRequest
	}
	if !clientStore.exists(tr.ClientID) {
		return AuthCode{}, "invalid client", http.StatusBadRequest
	}
	if !isValidClient(tr.ClientID, tr.ClientSecret, tr.RedirectURI) {
		return AuthCode{}, "unauthorized", http.StatusUnauthorized
	}

	authcode, ok := authcodeStore.Data[tr.Code]
	delete(authcodeStore.Data, tr.Code)
	if !ok {
		return AuthCode{}, "invalid code", http.StatusBadRequest
	}
	if authcode.ClientID != tr.ClientID || authcode.RedirectURI != tr.RedirectURI {
		return AuthCode{}, "invalid code", http.StatusBadRequest
	}
	if time.Now().After(authcode.ExpireAt) {
		return AuthCode{}, "code expired", http.StatusBadRequest
	}
	if authcode.CodeChallenge == "" {
		if tr.CodeVerifier != "" {
			return AuthCode{}, "PKCE failed", http.StatusBadRequest
		}
	}
	if tr.CodeVerifier == "" {
		return AuthCode{}, "PKCE failed", http.StatusBadRequest
	}
	switch authcode.CodeChallengeMethod {
	case "S256":
		src := sha256.Sum256([]byte(tr.CodeVerifier))
		target := base64.RawURLEncoding.EncodeToString(src[:])
		if authcode.CodeChallenge != target {
			return AuthCode{}, "PKCE failed", http.StatusBadRequest
		}
	case "plain":
		if tr.CodeVerifier != authcode.CodeChallenge {
			return AuthCode{}, "PKCE failed", http.StatusBadRequest
		}
	}
	return authcode, "", 0
}

func TokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tr := NewTokenRequest(r.Header.Get("Content-Type"), r)
	if tr == nil {
		http.Error(w, "invalid content type", http.StatusBadRequest)
		return
	}
	authcode, errMsg, statusCode := tr.Validate()
	if errMsg != "" {
		http.Error(w, errMsg, statusCode)
		return
	}

	accessToken, err := generateRandomStr(rand.Reader, 32)
	if err != nil {
		http.Error(w, "sever error", http.StatusInternalServerError)
		return
	}
	tokenType := "Bearer"
	expiresIn := 3600 //seconds(= 1hour)
	idToken := ""
	if strings.Contains(authcode.Scope, "openid") {
		it, err := issueIDToken(authcode)
		if err != nil {
			http.Error(w, "sever error", http.StatusInternalServerError)
			return
		}
		idToken = it
	}

	resp := map[string]any{
		"access_token": accessToken,
		"token_type":   tokenType,
		"expires_in":   expiresIn,
	}
	if idToken != "" {
		resp["id_token"] = idToken
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		http.Error(w, "sever error", http.StatusInternalServerError)
		return
	}
}

func issueIDToken(ac AuthCode) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": os.Getenv("JWT_ISS_URL"),
		"sub": ac.UserID,
		"aud": ac.ClientID,
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
	}
	if ac.Nonce != "" {
		claims["nonce"] = ac.Nonce
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(jwtSignedKey)
	if err != nil {
		return "", errors.New("failed to sign")
	}
	return signed, nil
}

// The returned string is url-safe because the generated random data is based64-encoded under the hood.
func generateRandomStr(r io.Reader, size int) (string, error) {
	b := make([]byte, size)
	if _, err := r.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
