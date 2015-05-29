package middleware

import (
  "net/http"
  "github.com/julienschmidt/httprouter"
  "github.com/gorilla/context"
  "github.com/wscherphof/secure"
)

const AUTH_KEY string = "b53d6eda-40f9-4d4b-a8ff-49e19d2f116f"

func Authenticated (handle httprouter.Handle) (httprouter.Handle) {
  return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    if authentication := secure.Authentication(w, r); authentication != nil {
      context.Set(r, AUTH_KEY, authentication)
      handle(w, r, ps)
    } else {
      secure.Challenge(w, r)
    }
  }
}

func AuthenticationHandler (handler http.Handler) (http.Handler) {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    context.Set(r, AUTH_KEY, secure.Authentication(w, r))
    handler.ServeHTTP(w, r)
  })
}

func Authentication (r *http.Request) interface{} {
  return context.Get(r, AUTH_KEY)
}
