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
  Upsert (*Config)
}

func Init (db DB, optionalConfig ...*Config) {
  // Build default config, based on possible given config
  config = &Config {}
  if len(optionalConfig) > 0 {
    config = optionalConfig[0]
  }
  config.TimeStamp = time.Now()
  if len(config.KeyPairs) != 4 {
    config.KeyPairs = [][]byte{securecookie.GenerateRandomKey(16), securecookie.GenerateRandomKey(16), securecookie.GenerateRandomKey(16), securecookie.GenerateRandomKey(16)}
    config.TimeStamp = time.Now()
  }
  if config.RedirectPath == "" {
    config.RedirectPath = "/login"
  }
  if config.TimeOut == 0 {
    config.TimeOut = 15 * 60 * time.Second
  }
  codecs = securecookie.CodecsFromPairs(config.KeyPairs...)
  if db == nil {
    return
  }
  go func () {
    for {
      if dbConfig := db.Fetch(); dbConfig == nil {
        // Upload default config to DB if there wasn't any
        db.Upsert(config)
      } else {
        // Replace default config with the one from DB
        config = dbConfig
        // Rotate keys if passed time out
        if time.Now().Sub(config.TimeStamp) >= config.TimeOut {
          config.KeyPairs[2], config.KeyPairs[3] = config.KeyPairs[0], config.KeyPairs[1]
          config.KeyPairs[0], config.KeyPairs[1] = securecookie.GenerateRandomKey(16), securecookie.GenerateRandomKey(16)
          config.TimeStamp = time.Now()
          db.Upsert(config)
          // TODO: consider what to log
          log.Print("INFO: Security keys rotated")
        }
        codecs = securecookie.CodecsFromPairs(config.KeyPairs...)
      }
      time.Sleep(config.TimeOut)
    }
  }()
}

// TODO: make session data flexible
type sessiontype struct {
  UID string
  Time time.Time
}

func LogIn (w http.ResponseWriter, uid string) {
  session := sessiontype {
    uid,
    time.Now(),
  }
  if encoded, err := securecookie.EncodeMulti("Token", session, codecs...); err == nil {
    http.SetCookie(w, &http.Cookie{
        Name:  "Token",
        Value: encoded,
        Path:  "/",
    })
  } else {
    panic(err)
  }
}

func Authenticate (w http.ResponseWriter, r *http.Request) string {
  var session sessiontype
  if cookie, err := r.Cookie("Token"); err != nil {
    return redirect(w, r)
  } else {
    if err := securecookie.DecodeMulti("Token", cookie.Value, &session, codecs...); err != nil {
      return redirect(w, r)
    }
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

// TODO: possible to add message with reason for redirect?
func redirect (w http.ResponseWriter, r *http.Request) string {
  http.Redirect(w, r, config.RedirectPath + "?return=" + r.URL.Path, 302)
  return ""
}
