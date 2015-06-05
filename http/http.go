/*
Package http provides middleware for ServeMux routes.
*/
package http

import (
	"github.com/wscherphof/secure"
	"net/http"
)

// SecureHandle enforces the presence of a valid token in the request, and
// redirects to the login page if it's missing.
func SecureHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if secure.Authentication(w, r) != nil {
			handler.ServeHTTP(w, r)
		} else {
			secure.Challenge(w, r)
		}
	})
}

// IfSecureHandle provides separate handle alternatives for requests with
// or without a valid token.
func IfSecureHandler(authenticated http.Handler, unauthenticated http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if secure.Authentication(w, r) != nil {
			authenticated.ServeHTTP(w, r)
		} else {
			unauthenticated.ServeHTTP(w, r)
		}
	})
}
