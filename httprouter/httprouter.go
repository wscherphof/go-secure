/*
Package httprouter provides middleware for julienschmidt's httprouter routes.
*/
package httprouter

import (
	"github.com/julienschmidt/httprouter"
	"github.com/wscherphof/secure"
	"net/http"
)

// IfSecureHandle provides separate handle alternatives for requests with
// or without a valid token.
func IfSecureHandle(authenticated httprouter.Handle, unauthenticated httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		if secure.Authentication(w, r, true) != nil {
			authenticated(w, r, ps)
		} else {
			unauthenticated(w, r, ps)
		}
	}
}
