package middleware

import (
  "net/http"
  "github.com/julienschmidt/httprouter"
  "github.com/gorilla/context"
  "github.com/wscherphof/secure"
)

const authenticationKey string = "b53d6eda-40f9-4d4b-a8ff-49e19d2f116f"

func Authenticate (handle httprouter.Handle) (httprouter.Handle) {
  return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    if authenitication := secure.Authenticate(w, r); authenitication != nil {
      context.Set(r, authenticationKey, authenitication)
      handle(w, r, ps)
    }
  }
}

func Authentication (r *http.Request) interface{} {
  return context.Get(r, authenticationKey)
}
