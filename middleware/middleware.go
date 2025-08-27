package middleware

import "net/http"

func Use(h http.Handler, midls ...func(http.Handler) http.Handler) http.Handler {
	if len(midls) == 0 {
		return h
	}
	chains := h
	for i := len(midls) - 1; i >= 0; i-- {
		chains = midls[i](chains)
	}
	return chains
}
