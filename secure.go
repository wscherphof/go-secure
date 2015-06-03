package secure

import (
	"encoding/gob"
	"errors"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"log"
	"net/http"
	"time"
)

type Config struct {
	KeyPairs     [][]byte
	TimeStamp    time.Time
	LogInPath    string
	LogOutPath   string
	TimeOut      time.Duration
	SyncInterval time.Duration
}

type DB interface {
	Fetch() *Config
	Upsert(*Config)
}

type Validate func(src interface{}) (dst interface{}, valid bool)

var validate = func(src interface{}) (dst interface{}, valid bool) {
	return src, true
}

var (
	ErrTokenNotSaved = errors.New("secure: failed to save the session token")
	ErrNoTLS         = errors.New("secure: logging in requires an encrypted conection")
)

var (
	config *Config
	store  *sessions.CookieStore
)

const (
	authKeyLen = 32
	encrKeyLen = 32
)

const (
	tokenName      = "authtoken"
	recordField    = "ddf77ee1-6a23-4980-8edc-ff4139e98f22"
	createdField   = "45595a0b-7756-428e-bae0-5f7ded324e92"
	validatedField = "fe6f1315-9aa1-4083-89a0-dcb6c198654b"
	returnField    = "eb8cacdd-d65f-441e-a63d-e4da69c2badc"
)

func configureStore() {
	store = sessions.NewCookieStore(config.KeyPairs...)
	store.Options = &sessions.Options{
		MaxAge: int(config.TimeOut / time.Second),
		Secure: true,
		Path:   "/",
	}
}

func Configure(record interface{}, db DB, validateFunc Validate, optionalConfig ...*Config) {
	gob.Register(record)
	gob.Register(time.Now())
	config = &Config{
		LogInPath:    "/session",
		LogOutPath:   "/",
		TimeOut:      6 * 30 * 24 * time.Hour,
		SyncInterval: 5 * time.Minute,
		KeyPairs: [][]byte{
			securecookie.GenerateRandomKey(authKeyLen),
			securecookie.GenerateRandomKey(encrKeyLen),
			securecookie.GenerateRandomKey(authKeyLen),
			securecookie.GenerateRandomKey(encrKeyLen),
		},
		TimeStamp: time.Now(),
	}
	if len(optionalConfig) > 0 {
		opt := optionalConfig[0]
		if len(opt.LogInPath) > 0 {
			config.LogInPath = opt.LogInPath
		}
		if len(opt.LogOutPath) > 0 {
			config.LogOutPath = opt.LogOutPath
		}
		if opt.TimeOut > 0 {
			config.TimeOut = opt.TimeOut
		}
		if opt.SyncInterval > 0 {
			config.SyncInterval = opt.SyncInterval
		}
		if len(opt.KeyPairs) == 4 {
			config.KeyPairs = opt.KeyPairs
		}
	}
	configureStore()
	if db != nil {
		go func() {
			for {
				sync(db)
				time.Sleep(config.SyncInterval)
			}
		}()
	}
	if validateFunc != nil {
		validate = validateFunc
	}
}

func sync(db DB) {
	if dbConfig := db.Fetch(); dbConfig == nil {
		// Upload current (default) config to DB if there wasn't any
		db.Upsert(config)
	} else {
		// Replace current config with the one from DB
		config = dbConfig
		// Rotate keys if timed out
		if time.Now().Sub(config.TimeStamp) > config.TimeOut {
			config.KeyPairs = [][]byte{
				securecookie.GenerateRandomKey(authKeyLen),
				securecookie.GenerateRandomKey(encrKeyLen),
				config.KeyPairs[0],
				config.KeyPairs[1],
			}
			config.TimeStamp = time.Now()
			db.Upsert(config)
			log.Println("INFO: Security keys rotated")
		}
		configureStore()
	}
}

func getToken(r *http.Request) (session *sessions.Session) {
	session, _ = store.Get(r, tokenName)
	return
}

func LogIn(w http.ResponseWriter, r *http.Request, record interface{}, redirect bool) (err error) {
	session := getToken(r)
	if session.Values[createdField] == nil {
		session.Values[createdField] = time.Now()
	}
	session.Values[recordField] = record
	session.Values[validatedField] = time.Now()
	if r.TLS == nil {
		err = ErrNoTLS
	} else if e := session.Save(r, w); e != nil {
		err = ErrTokenNotSaved
	} else if redirect {
		path := session.Values[returnField]
		if path == nil {
			path = config.LogOutPath
		}
		http.Redirect(w, r, path.(string), http.StatusSeeOther)
	}
	return
}

func sessionCurrent(session *sessions.Session) (current bool) {
	if created := session.Values[createdField]; created == nil {
	} else {
		current = time.Since(created.(time.Time)) < config.TimeOut
	}
	return
}

func accountCurrent(session *sessions.Session, w http.ResponseWriter, r *http.Request) (current bool) {
	if validated := session.Values[validatedField]; validated == nil {
	} else if cur := time.Since(validated.(time.Time)) < config.SyncInterval; cur {
		current = true
	} else if record, cur := validate(session.Values[recordField]); cur {
		session.Values[recordField] = record
		session.Values[validatedField] = time.Now()
		_ = session.Save(r, w)
		current = true
	}
	return
}

func Authentication(w http.ResponseWriter, r *http.Request) (record interface{}) {
	session := getToken(r)
	if !session.IsNew && sessionCurrent(session) && accountCurrent(session, w, r) {
		record = session.Values[recordField]
	}
	return
}

func clearToken(r *http.Request) (session *sessions.Session) {
	session = getToken(r)
	delete(session.Values, recordField)
	delete(session.Values, createdField)
	delete(session.Values, validatedField)
	return
}

func Challenge(w http.ResponseWriter, r *http.Request) {
	session := clearToken(r)
	session.Values[returnField] = r.URL.Path
	_ = session.Save(r, w)
	http.Redirect(w, r, config.LogInPath, http.StatusSeeOther)
}

func LogOut(w http.ResponseWriter, r *http.Request, redirect bool) {
	session := clearToken(r)
	session.Options = &sessions.Options{
		MaxAge: -1,
	}
	_ = session.Save(r, w)
	if redirect {
		http.Redirect(w, r, config.LogOutPath, http.StatusSeeOther)
	}
}
