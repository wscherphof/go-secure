package secure

import (
  "time"
  "net/http"
  "log"
  "github.com/gorilla/securecookie"
)

type Config struct {
  KeyPairs [][]byte
  TimeStamp time.Time
  RedirectPath string
  TimeOut time.Duration
}

var (
  config *Config
  codecs []securecookie.Codec
)

type DB interface {
  Fetch () *Config
  Update (*Config)
}

func Init (db DB) {
  config = &Config {
    KeyPairs: [][]byte{securecookie.GenerateRandomKey(16), securecookie.GenerateRandomKey(16), securecookie.GenerateRandomKey(16), securecookie.GenerateRandomKey(16)},
    TimeStamp: time.Now(),
    RedirectPath: "/login",
    TimeOut: 15 * 60 * time.Second, 
  }
  if db == nil {
    return
  }
  go func () {
    for {
      config = db.Fetch()
      if time.Now().Sub(config.TimeStamp) >= config.TimeOut {
        config.KeyPairs[2], config.KeyPairs[3] = config.KeyPairs[0], config.KeyPairs[1]
        config.KeyPairs[0], config.KeyPairs[1] = securecookie.GenerateRandomKey(16), securecookie.GenerateRandomKey(16)
        config.TimeStamp = time.Now()
        db.Update(config)
        // TODO: consider what to log
        log.Print("INFO: updated Secure config")
      }
      codecs = securecookie.CodecsFromPairs(config.KeyPairs...)
      time.Sleep(config.TimeOut)
    }
  }()
}

type Session struct {
  UID string
  Time time.Time
}

func LogIn (w http.ResponseWriter, uid string) {
  session := Session{
    uid,
    time.Now(),
  }
  encoded, err := securecookie.EncodeMulti("Token", session, codecs...)
  if err != nil {
    panic(err)
  }
  http.SetCookie(w, &http.Cookie{
      Name:  "Token",
      Value: encoded,
      Path:  "/",
  })
}

func Authenticate (w http.ResponseWriter, r *http.Request) string {
  cookie, err := r.Cookie("Token")
  if err != nil {
    return redirect(w, r)
  }
  var session Session
  err = securecookie.DecodeMulti("Token", cookie.Value, &session, codecs...)
  if err != nil {
    return redirect(w, r)
  }
  // Verify session time out
  if time.Since(session.Time) > config.TimeOut {
    return redirect(w, r)
  } else {
    // Update the Token cookie to include the current time
    update(w, session.UID)
    return session.UID
  }
}

func update (w http.ResponseWriter, uid string) {
  LogIn(w, uid)
}

func redirect (w http.ResponseWriter, r *http.Request) string {
  http.Redirect(w, r, config.RedirectPath + "?return=" + r.URL.Path, 302)
  return ""
}
