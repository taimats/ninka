package handler_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/taimats/ninka/handler"
	"golang.org/x/crypto/bcrypt"
)

type testRequest struct {
	method string
	path   string
	body   any
}

type wantResponse struct {
	body       string
	statusCode int
}

func testHandler(t *testing.T, h http.HandlerFunc, r *http.Request) (res *http.Response, body string) {
	t.Helper()

	w := httptest.NewRecorder()
	h(w, r)

	res = w.Result()
	var buf bytes.Buffer
	io.Copy(&buf, res.Body)

	return res, buf.String()
}

func newJSONBody[T any](t *testing.T, v T) io.Reader {
	var r bytes.Buffer
	err := json.NewEncoder(&r).Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	return &r
}

func newJSONString[T any](t *testing.T, v T) string {
	var r bytes.Buffer
	err := json.NewEncoder(&r).Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	return r.String()
}

func cleanupStore[K comparable, V any](t *testing.T, s *handler.Store[K, V]) {
	t.Helper()
	for k := range s.Data {
		delete(s.Data, k)
	}
	if len(s.Data) != 0 {
		t.Fatalf("failed to clean up %sStore\n", s.Name)
	}
}

func TestRegisterHandler(t *testing.T) {
	tests := []struct {
		desc string
		req  testRequest
		want wantResponse
	}{
		{
			desc: "pass_01",
			req: testRequest{
				method: "POST",
				path:   "/register",
				body:   handler.NewClient("test", "test_secret", "http://localhost:8080/test"),
			},
			want: wantResponse{
				body:       "",
				statusCode: http.StatusCreated,
			},
		},
		{
			desc: "fail_01: invalid method",
			req: testRequest{
				method: "GET",
				path:   "/register",
				body:   handler.NewClient("test", "test_secret", "http://localhost:8080/test"),
			},
			want: wantResponse{
				body:       "",
				statusCode: http.StatusMethodNotAllowed,
			},
		},
		{
			desc: "fail_02: invalid body",
			req: testRequest{
				method: "POST",
				path:   "/register",
				body:   handler.NewClient("", "", "http://localhost:8080/test"),
			},
			want: wantResponse{
				body:       "body should not be empty\n",
				statusCode: http.StatusBadRequest,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			t.Cleanup(func() {
				cleanupStore(t, handler.ClientStore)
			})
			req, err := http.NewRequest(tt.req.method, tt.req.path, newJSONBody(t, tt.req.body))
			if err != nil {
				t.Fatal(err)
			}

			res, body := testHandler(t, handler.RegisterHanlder, req)

			if body != tt.want.body {
				t.Errorf("Body is not equal: (got=%s, want=%s)\n", body, tt.want.body)
			}
			if res.StatusCode != tt.want.statusCode {
				t.Errorf("StatusCode is not equal: (got=%d, want=%d)\n", res.StatusCode, tt.want.statusCode)
			}
		})
	}
}

func TestLoginHandler(t *testing.T) {
	cl := handler.NewClient("test", "test_secret", "http://localhost:8080/test")
	hashed, err := bcrypt.GenerateFromPassword([]byte("test_secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	cl.Secret = handler.Password(hashed)
	err = handler.ClientStore.Add(cl.ID, cl)
	if err != nil {
		t.Fatal(err)
	}
	q := &url.Values{}
	q.Add("id", "test")
	q.Add("secret", "test_secret")
	q.Add("redirect", "http://localhost:8080/test")

	tests := []struct {
		desc string
		req  testRequest
		want wantResponse
	}{
		{
			desc: "pass_01",
			req: testRequest{
				method: "POST",
				path:   fmt.Sprintf("/login?%s", q.Encode()),
				body:   "",
			},
			want: wantResponse{
				body:       "",
				statusCode: http.StatusFound,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			t.Cleanup(func() {
				cleanupStore(t, handler.ClientStore)
			})

			req, err := http.NewRequest(tt.req.method, tt.req.path, nil)
			if err != nil {
				t.Fatal(err)
			}

			res, body := testHandler(t, handler.LoginHandler, req)

			if body != tt.want.body {
				t.Errorf("Body is not equal: (got=%s, want=%s)\n", body, tt.want.body)
			}
			if res.StatusCode != tt.want.statusCode {
				t.Errorf("StatusCode is not equal: (got=%d, want=%d)\n", res.StatusCode, tt.want.statusCode)
			}
			if len(res.Cookies()) == 0 {
				t.Errorf("Cookie should not be empty: (length=%d)", len(res.Cookies()))
			}
			url, err := res.Location()
			if err != nil {
				t.Errorf("redirect location is not set")
			}
			if url.String() != "http://localhost:8080/test" {
				t.Errorf("redirect location is not equal: (got=%s, want=%s)", url.String(), "http://localhost:8080/test")
			}
		})
	}
}

func TestAuthorizeHandler(t *testing.T) {
	cl := handler.NewClient("test", "test_secret", "http://localhost:8080/test")
	handler.ClientStore.Add(cl.ID, cl)

	sessionID := "session_test"
	handler.SessionStore.Add(sessionID, cl.ID)

	q := &url.Values{}
	q.Add("response_type", "code")
	q.Add("client_id", "test")
	q.Add("redirect_uri", "http://localhost:8080/test")
	q.Add("state", "state_test")
	q.Add("scope", "openid")
	q.Add("code_challenge", "test_challenge")
	q.Add("code_challenge_method", "S256")
	q.Add("nonce", "nonce_test")

	tests := []struct {
		desc string
		req  testRequest
		want wantResponse
	}{
		{
			desc: "pass_01",
			req: testRequest{
				method: "POST",
				path:   fmt.Sprintf("/authorize?%s", q.Encode()),
				body:   "",
			},
			want: wantResponse{
				body:       "",
				statusCode: http.StatusFound,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			t.Cleanup(func() {
				cleanupStore(t, handler.SessionStore)
				cleanupStore(t, handler.ClientStore)
				cleanupStore(t, handler.AuthcodeStore)
			})
			req, err := http.NewRequest(tt.req.method, tt.req.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(&http.Cookie{
				Name:     "session_id",
				Value:    sessionID,
				Path:     "/",
				HttpOnly: true,
			})

			res, body := testHandler(t, handler.AuthorizeHanler, req)

			if body != tt.want.body {
				t.Errorf("Body is not equal: (got=%s, want=%s)\n", body, tt.want.body)
			}
			if res.StatusCode != tt.want.statusCode {
				t.Errorf("StatusCode is not equal: (got=%d, want=%d)\n", res.StatusCode, tt.want.statusCode)
			}
			url, err := res.Location()
			if err != nil {
				t.Errorf("redirect location is not set: (got=%s)", url.String())
			}
			if url.Query().Get("code") == "" {
				t.Errorf("query code should be included: (got=%s)", url.Query().Get("code"))
			}
			if url.Query().Get("state") == "" {
				t.Errorf("query state should be included: (got=%s)", url.Query().Get("state"))
			}
			if len(handler.AuthcodeStore.Data) == 0 {
				t.Errorf("authcodeStore should not be empty: (length: %d)", len(handler.AuthcodeStore.Data))
			}
		})
	}
}

func TestTokenHandler(t *testing.T) {
	cl := handler.NewClient("test", "test_secret", "http://localhost:8080/test")
	handler.ClientStore.Add(cl.ID, cl)

	sessionID := "session_test"
	handler.SessionStore.Add(sessionID, cl.ID)

	q := &url.Values{}
	q.Add("response_type", "code")
	q.Add("client_id", "test")
	q.Add("redirect_uri", "http://localhost:8080/test")
	q.Add("state", "state_test")
	q.Add("scope", "openid")
	q.Add("code_challenge", "test_challenge")
	q.Add("code_challenge_method", "S256")
	q.Add("nonce", "nonce_test")

	tests := []struct {
		desc string
		req  testRequest
		want wantResponse
	}{
		{
			desc: "pass_01",
			req: testRequest{
				method: "POST",
				path:   fmt.Sprintf("/authorize?%s", q.Encode()),
				body:   "",
			},
			want: wantResponse{
				body:       "",
				statusCode: http.StatusFound,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			t.Cleanup(func() {
				cleanupStore(t, handler.SessionStore)
				cleanupStore(t, handler.ClientStore)
				cleanupStore(t, handler.AuthcodeStore)
			})
			req, err := http.NewRequest(tt.req.method, tt.req.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(&http.Cookie{
				Name:     "session_id",
				Value:    sessionID,
				Path:     "/",
				HttpOnly: true,
			})

			res, body := testHandler(t, handler.AuthorizeHanler, req)

			if body != tt.want.body {
				t.Errorf("Body is not equal: (got=%s, want=%s)\n", body, tt.want.body)
			}
			if res.StatusCode != tt.want.statusCode {
				t.Errorf("StatusCode is not equal: (got=%d, want=%d)\n", res.StatusCode, tt.want.statusCode)
			}
			url, err := res.Location()
			if err != nil {
				t.Errorf("redirect location is not set: (got=%s)", url.String())
			}
			if url.Query().Get("code") == "" {
				t.Errorf("query code should be included: (got=%s)", url.Query().Get("code"))
			}
			if url.Query().Get("state") == "" {
				t.Errorf("query state should be included: (got=%s)", url.Query().Get("state"))
			}
			if len(handler.AuthcodeStore.Data) == 0 {
				t.Errorf("authcodeStore should not be empty: (length: %d)", len(handler.AuthcodeStore.Data))
			}
		})
	}
}
