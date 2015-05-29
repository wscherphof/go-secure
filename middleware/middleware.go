package middleware

import (
  "net/http"
  "github.com/wscherphof/secure"
)

func AuthenticationHandler (handler http.Handler) (http.Handler) {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    setAuthentication(r, secure.Authentication(w, r))
    handler.ServeHTTP(w, r)
  })
}

func Authentication (r *http.Request) interface{} {
  return getAuthentication(r)
}
