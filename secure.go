package secure

import (
  "time"
  "net/http"
  "log"
  "encoding/gob"
  "github.com/gorilla/sessions"
  "github.com/gorilla/securecookie"
)

type Config struct {
  KeyPairs [][]byte
  TimeStamp time.Time
  RedirectPath string
  TimeOut time.Duration
}

type DB interface {
  Fetch () *Config
  Upsert (*Config)
}

var (
  config *Config
  store *sessions.CookieStore
)

const (
  LEN_KEY_AUTH = 32
  LEN_KEY_ENCR = 32
)

func Init (db DB, optionalConfig ...*Config) {
  gob.Register(time.Now())
  // Build default config, based on possible given config
  config = &Config {}
  if len(optionalConfig) > 0 {
    config = optionalConfig[0]
  }
  config.TimeStamp = time.Now()
  if len(config.KeyPairs) != 4 {
    config.KeyPairs = [][]byte{
      securecookie.GenerateRandomKey(LEN_KEY_AUTH),
      securecookie.GenerateRandomKey(LEN_KEY_ENCR),
      securecookie.GenerateRandomKey(LEN_KEY_AUTH),
      securecookie.GenerateRandomKey(LEN_KEY_ENCR),
    }
  }
  if config.RedirectPath == "" {
    config.RedirectPath = "/login"
  }
  if config.TimeOut == 0 {
    config.TimeOut = 15 * 60 * time.Second
  }
  // Use keys from default config
  updateKeys()
  if db != nil {
    go func () {
      for {
        sync(db)
        time.Sleep(config.TimeOut)
      }
    }()
  }
}

func updateKeys () {
  store = sessions.NewCookieStore(config.KeyPairs...)
}

func sync (db DB) {
  if dbConfig := db.Fetch(); dbConfig == nil {
    // Upload default config to DB if there wasn't any
    db.Upsert(config)
  } else {
    // Replace current config with the one from DB
    config = dbConfig
    // Rotate keys if passed time out
    if time.Now().Sub(config.TimeStamp) >= config.TimeOut {
      config.KeyPairs = [][]byte{
        securecookie.GenerateRandomKey(LEN_KEY_AUTH),
        securecookie.GenerateRandomKey(LEN_KEY_ENCR),
        config.KeyPairs[0],
        config.KeyPairs[1],
      }
      config.TimeStamp = time.Now()
      db.Upsert(config)
      // TODO: consider what to log
      log.Print("INFO: Security keys rotated")
    }
    // Update keys from new config
    // (Even if we haven't just rotated the keys in DB, a collaborator process most probably has done so)
    updateKeys()
  }
}

// TODO: make session data flexible?
func LogIn (w http.ResponseWriter, r *http.Request, uid string) {
  session, _ := store.Get(r, "Token")
  session.Values["uid"] = uid
  save(w, r)
}

func save (w http.ResponseWriter, r *http.Request) {
  session, _ := store.Get(r, "Token")
  session.Values["time"] = time.Now()
  if err := session.Save(r, w); err != nil {
    // TODO: don't panic
    panic(err)
  }
}

func Authenticate (w http.ResponseWriter, r *http.Request) string {
  session, _ := store.Get(r, "Token")
  if session.IsNew {
    return redirect(w, r)
  }
  // Verify session time out
  if time.Since(session.Values["time"].(time.Time)) > config.TimeOut {
    return redirect(w, r)
  } else {
    // Update the Token cookie to include the current time
    save(w, r)
    return session.Values["uid"].(string)
  }
}

// TODO: possible to add message with reason for redirect?
func redirect (w http.ResponseWriter, r *http.Request) string {
  http.Redirect(w, r, config.RedirectPath + "?return=" + r.URL.Path, 302)
  return ""
}

func LogOut (w http.ResponseWriter, r *http.Request) {
  session, _ := store.Get(r, "Token")
  session.Options = &sessions.Options{
    MaxAge: -1,
  }
  save(w, r)
}
