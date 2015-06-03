package middleware

import (
	"github.com/gorilla/context"
	"github.com/wscherphof/secure"
	"net/http"
)

const AUTH_KEY string = "b53d6eda-40f9-4d4b-a8ff-49e19d2f116f"

func AuthenticationHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authentication := secure.Authentication(w, r)
		context.Set(r, AUTH_KEY, authentication)
		handler.ServeHTTP(w, r)
	})
}

func Authentication(r *http.Request) interface{} {
	return context.Get(r, AUTH_KEY)
}
