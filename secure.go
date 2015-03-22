package secure

import (
  "time"
  "net/http"
  "log"
  "github.com/gorilla/securecookie"
)

type Secret struct {
  Key string
  Time time.Time
}

type Config struct {
  Secret Secret
  RedirectPath string
  TimeOut time.Duration
}

var config = Config {
  Secret: Secret {
    Key: "qwerty",
    Time: time.Now(),
  },
  RedirectPath: "/login",
  TimeOut: 15 * 60 * time.Second, 
}

var sc *securecookie.SecureCookie

func Init (fetch func () *Config) {
  go func () {
    for {
      // TODO:
      // - use the new key for new sessions
      // - keep the old key to try if old sessions fail on the new key
      // - ditch the old key on the next update; no more than 2 key alternatives
      config = *fetch()
      sc = securecookie.New([]byte(config.Secret.Key), nil)
      log.Print("INFO: fetched Secure config")
      time.Sleep(config.TimeOut)
    }
  }()
}

type Session struct {
  UID string
  Time time.Time
}

func LogIn (w http.ResponseWriter, uid string) {
  encoded, err := sc.Encode("Token", Session{
    uid,
    time.Now(),
  })
  if err != nil {
    panic(err)
  }
  http.SetCookie(w, &http.Cookie{
      Name:  "Token",
      Value: encoded,
      Path:  "/",
  })
}

func Update (w http.ResponseWriter, uid string) {
  LogIn(w, uid)
}

func Authenticate (w http.ResponseWriter, r *http.Request) string {
  if cookie, err := r.Cookie("Token"); err == nil {
    var session Session
    err = sc.Decode("Token", cookie.Value, &session)
    if err != nil {
      panic(err)
    }
    // Verify the session hasn't timed out
    since := time.Since(session.Time)
    if since < config.TimeOut {
      // Update the Token cookie to include the current time
      Update(w, session.UID)
      return session.UID
    }
  }
  http.Redirect(w, r, config.RedirectPath + "?return=" + r.URL.Path, 302)
  return ""
}
