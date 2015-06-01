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
  SyncInterval time.Duration
}

type DB interface {
  Fetch () *Config
  Upsert (*Config)
}

type Validate func(src interface{})(dst interface{}, valid bool)

var (
  config *Config
  store *sessions.CookieStore
  validate Validate
)

var (
  ErrTokenNotSaved = errors.New("secure: failed to save the session token")
  ErrNoTLS = errors.New("secure: logging in requires an encrypted conection")
)

const (
  LEN_KEY_AUTH = 32
  LEN_KEY_ENCR = 32
)

const (
  TOKEN     = "authentication-token"
  RECORD    = "ddf77ee1-6a23-4980-8edc-ff4139e98f22"
  CREATED   = "45595a0b-7756-428e-bae0-5f7ded324e92"
  VALIDATED = "fe6f1315-9aa1-4083-89a0-dcb6c198654b"
  RETURN    = "eb8cacdd-d65f-441e-a63d-e4da69c2badc"
)

func Configure(record interface{}, db DB, validateFunc Validate, optionalConfig ...*Config) {
  gob.Register(record)
  gob.Register(time.Now())
  validate = validateFunc
  // Build default config, based on possible given config
  config = &Config{}
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
    config.TimeOut = 6 * 30 * 24 * time.Hour
  }
  if config.SyncInterval == 0 {
    config.SyncInterval = 5 * time.Minute
  }
  // Use keys from default config
  updateKeys()
  if db != nil {
    go func() {
      for {
        sync(db)
        time.Sleep(config.SyncInterval)
      }
    }()
  }
}

func updateKeys() {
  store = sessions.NewCookieStore(config.KeyPairs...)
  store.Options = &sessions.Options{
    MaxAge: int(config.TimeOut / time.Second),
    Secure: true,
  }
}

func sync(db DB) {
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
    // (even if we haven't rotated the keys in DB just now, a collaborator process might have)
    updateKeys()
  }
}

func getToken(r *http.Request) (session *sessions.Session) {
  session, _ = store.Get(r, TOKEN)
  return
}

func LogIn(w http.ResponseWriter, r *http.Request, record interface{}, redirect bool) (err error) {
  session := getToken(r)
  session.Options = store.Options
  session.Values[RECORD]    = record
  session.Values[CREATED]   = time.Now()
  session.Values[VALIDATED] = time.Now()
  redirectPath := session.Values[RETURN]
  if r.TLS == nil {
    err = ErrNoTLS
  } else if err = session.Save(r, w); err != nil {
    err = ErrTokenNotSaved
  } else if redirect {
    if redirectPath == nil {
      redirectPath = config.LogOutPath
    }
    http.Redirect(w, r, redirectPath.(string), http.StatusSeeOther)
  }
  return
}

func sessionCurrent(session *sessions.Session) (current bool) {
  created := session.Values[CREATED]
  if created != nil && time.Since(created.(time.Time)) < config.TimeOut {
    current = true
  }
  return
}

func accountCurrent(session *sessions.Session, w http.ResponseWriter, r *http.Request) (current bool) {
  validated := session.Values[VALIDATED]
  if validated == nil {
  } else if cur := (time.Since(validated.(time.Time)) < config.SyncInterval); cur {
    current = true
  } else if record, cur := validate(session.Values[RECORD]); cur {
    session.Values[RECORD]    = record
    session.Values[VALIDATED] = time.Now()
    _ = session.Save(r, w)
    current = true
  }
  return
}

func Authentication(w http.ResponseWriter, r *http.Request) (record interface{}) {
  session := getToken(r)
  if !session.IsNew && sessionCurrent(session) && accountCurrent(session, w, r) {
    record = session.Values[RECORD]
  }
  return
}

func clear(session *sessions.Session) {
  delete(session.Values, RECORD)
  delete(session.Values, CREATED)
  delete(session.Values, VALIDATED)
}

func Challenge(w http.ResponseWriter, r *http.Request) {
  session := getToken(r)
  clear(session)
  session.Values[RETURN] = r.URL.Path
  _ = session.Save(r, w)
  http.Redirect(w, r, config.LogInPath, http.StatusSeeOther)
}

func LogOut(w http.ResponseWriter, r *http.Request, redirect bool) {
  session := getToken(r)
  clear(session)
  session.Options = &sessions.Options{
    MaxAge: -1,
  }
  _ = session.Save(r, w)
  if redirect {
    http.Redirect(w, r, config.LogOutPath, http.StatusSeeOther)
  }
}
