package secure

import (
  "time"
  "net/http"
  "log"
  "errors"
  "encoding/gob"
  "github.com/gorilla/sessions"
  "github.com/gorilla/securecookie"
)

type Config struct {
  KeyPairs [][]byte
  TimeStamp time.Time
  LogInPath string
  LogOutPath string
  TimeOut time.Duration
}

type DB interface {
  Fetch () *Config
  Upsert (*Config)
}

var (
  config *Config
  store *sessions.CookieStore
  ErrTokenNotSaved = errors.New("secure: failed to save the session token")
)

const (
  LEN_KEY_AUTH = 32
  LEN_KEY_ENCR = 32
)

func Init (account interface{}, db DB, optionalConfig ...*Config) {
  gob.Register(account)
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
  if config.LogInPath == "" {
    config.LogInPath = "/session"
  }
  if config.LogOutPath == "" {
    config.LogOutPath = "/"
  }
  if config.TimeOut == 0 {
    config.TimeOut = 15 * 60 * time.Second
  }
  // Use keys from default config
  updateKeys()
  if db != nil {
    go func() {
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
    if time.Now().Sub(config.TimeStamp) > config.TimeOut {
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
    // (even if we haven't rotated the keys in DB just now, a collaborator process most probably has)
    updateKeys()
  }
}

func LogIn (w http.ResponseWriter, r *http.Request, account interface{}) (err error) {
  session, _ := store.Get(r, "Token")
  session.Values["account"] = account
  session.Values["authenticated"] = time.Now()
  var path = "/"
  if flashes := session.Flashes("return"); len(flashes) > 0 {
    path = flashes[0].(string)
  }
  if err = session.Save(r, w); err != nil {
    err = ErrTokenNotSaved
  } else {
    http.Redirect(w, r, path, http.StatusSeeOther)
  }
  return
}

func Authenticate (w http.ResponseWriter, r *http.Request) (account interface{}) {
  session, _ := store.Get(r, "Token")
  if session.IsNew || session.Values["authenticated"] == nil || time.Since(session.Values["authenticated"].(time.Time)) > config.TimeOut {
    session.AddFlash(r.URL.Path, "return")
    defer http.Redirect(w, r, config.LogInPath, http.StatusSeeOther)
  } else {
    account = session.Values["account"]
    session.Values["authenticated"] = time.Now()
  }
  _ = session.Save(r, w)
  return
}

func LogOut (w http.ResponseWriter, r *http.Request) {
  session, _ := store.Get(r, "Token")
  session.Options = &sessions.Options{
    MaxAge: -1,
  }
  _ = session.Save(r, w)
  http.Redirect(w, r, config.LogOutPath, http.StatusSeeOther)
}
