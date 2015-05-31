package httprouter

import (
  "net/http"
  "github.com/julienschmidt/httprouter"
  "github.com/wscherphof/secure"
  "github.com/wscherphof/secure/middleware"
)

func SecureHandle (handle httprouter.Handle) (httprouter.Handle) {
  return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    if authentication := secure.Authentication(w, r); authentication != nil {
      middleware.SetAuthentication(r, authentication)
      handle(w, r, ps)
    } else {
      secure.Challenge(w, r)
    }
  }
}

func IfSecureHandle (authenticated httprouter.Handle, unauthenticated httprouter.Handle) (httprouter.Handle) {
  return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    if authentication := secure.Authentication(w, r); authentication != nil {
      middleware.SetAuthentication(r, authentication)
      authenticated(w, r, ps)
    } else {
      unauthenticated(w, r, ps)
    }
  }
}
