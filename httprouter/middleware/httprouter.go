package middleware

import (
  "net/http"
  "github.com/julienschmidt/httprouter"
  "github.com/gorilla/context"
  "github.com/wscherphof/secure"
)

const AUTH_KEY string = "b53d6eda-40f9-4d4b-a8ff-49e19d2f116f"

var UpdateAuthentication = secure.UpdateAuthentication

// TODO: DRY

func Authenticate (handle httprouter.Handle) (httprouter.Handle) {
  return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    authentication := secure.Authenticate(w, r, true)
    if authentication != nil {
      context.Set(r, AUTH_KEY, authentication)
      handle(w, r, ps)
    }
  }
}

func IfAuthenticate (handle httprouter.Handle) (httprouter.Handle) {
  return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    authentication := secure.Authenticate(w, r, false)
    context.Set(r, AUTH_KEY, authentication)
    handle(w, r, ps)
  }
}

func Authentication (r *http.Request) interface{} {
  return context.Get(r, AUTH_KEY)
}
