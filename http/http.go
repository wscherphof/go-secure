/*
Package http provides middleware for ServeMux routes.
*/
package http

import (
	"github.com/wscherphof/secure"
	"net/http"
)

// IfSecureHandle provides separate handle alternatives for requests with
// or without a valid token.
func IfSecureHandler(authenticated http.Handler, unauthenticated http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if secure.Authentication(w, r, true) != nil {
			authenticated.ServeHTTP(w, r)
		} else {
			unauthenticated.ServeHTTP(w, r)
		}
	})
}
