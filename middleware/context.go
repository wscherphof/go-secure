package middleware

import (
  "net/http"
  "github.com/gorilla/context"
)

const AUTH_KEY string = "b53d6eda-40f9-4d4b-a8ff-49e19d2f116f"

func setAuthentication (r *http.Request, authentication interface{}) {
  context.Set(r, AUTH_KEY, authentication)
}

func getAuthentication (r *http.Request) (authentication interface{}) {
  return context.Get(r, AUTH_KEY)
}
