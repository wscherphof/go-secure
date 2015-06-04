/*
Package httprouter provides middleware for julienschmidt's httprouter routes.
*/
package httprouter

import (
	"github.com/julienschmidt/httprouter"
	"github.com/wscherphof/secure"
	"github.com/wscherphof/secure/middleware"
	"net/http"
)

/*
SecureHandle enforces the presence of a valid token in the request, and
redirects to the login page if it's missing.
*/
func SecureHandle(handle httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		if middleware.Authentication(r) != nil {
			handle(w, r, ps)
		} else {
			secure.Challenge(w, r)
		}
	}
}

/*
IfSecureHandle provides separate handle alternatives for requests with
or without a valid token.
*/
func IfSecureHandle(authenticated httprouter.Handle, unauthenticated httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		if middleware.Authentication(r) != nil {
			authenticated(w, r, ps)
		} else {
			unauthenticated(w, r, ps)
		}
	}
}
