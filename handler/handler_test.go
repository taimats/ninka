package handler_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/taimats/ninka/handler"
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
