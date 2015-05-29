package middleware

import (
  "net/http"
  "github.com/julienschmidt/httprouter"
  "github.com/wscherphof/secure"
)

func SecureHandle (handle httprouter.Handle) (httprouter.Handle) {
  return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    if authentication := secure.Authentication(w, r); authentication != nil {
      setAuthentication(r, authentication)
      handle(w, r, ps)
    } else {
      secure.Challenge(w, r)
    }
  }
}
