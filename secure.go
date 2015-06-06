/*
Package secure manages client side session tokens for stateless web
applications.

Tokens are stored as an http cookie. An encrypted connection (https) is
required.

Call 'Configure()' once to provide the information for the package to operate,
including the type of data that will be stored in the token. The actual
configuration parameters are stored in a 'Config' type struct, which can be
synced with an external database, through the 'DB' interface.

Once configured, call 'Authentication()' to retrieve the data from the token.
It will redirect to a login page if no valid token is present (unless the
`optional` argument was `true`). 'LogIn()' creates a new token, stores the
provided data in it, and redirects back to the page that required the
authentication.
'Update()' updates the token data. To delete the token, call 'LogOut()'.

You'll probably want to wrap 'Authentication()' in a function that converts the
'interface{}' result to the type that you use for the token data.
*/
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

var (

	// ErrTokenNotSaved is returned by LogIn() if it couldn't set the cookie.
	ErrTokenNotSaved = errors.New("secure: failed to save the session token")

	// ErrNoTLS is returned by LogIn() if the connection isn't encrypted
	// (https)
	ErrNoTLS = errors.New("secure: logging in requires an encrypted conection")
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

// Config holds the package's configuration parameters.
// Can be synced with an external database, through the DB interface.
type Config struct {

	// LogInPath is the URL where Authentication() redirects to; a log in form
	// should be served here.
	// Default value is "/session".
	LogInPath string

	// LogOutPath is the URL where LogOut() redirects to.
	// Default value is "/".
	LogOutPath string

	// TimeOut is when a token expires (time after LogIn())
	// Default value is 6 * 30 days.
	TimeOut time.Duration

	// SyncInterval is how often the configuration is synced with an external
	// database. SyncInterval also determines whether it's time to have the
	// token data checked by the Validate function.
	// Default value is 5 minutes.
	SyncInterval time.Duration

	// KeyPairs are 4 32-long byte arrays (two pairs of an authentication key
	// and an encryption key); the 2nd pair is used for key rotation.
	// Default value is newly generated keys.
	// Keys get rotated on the first sync cycle after a TimeOut interval -
	// new tokens use the new keys; existing tokens continue to use the old
	// keys.
	KeyPairs [][]byte

	// TimeStamp is when the latest key pair was generated.
	TimeStamp time.Time
}

var config = &Config{
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

var store *sessions.CookieStore

func configureStore() {
	store = sessions.NewCookieStore(config.KeyPairs...)
	store.Options = &sessions.Options{
		MaxAge: int(config.TimeOut / time.Second),
		Secure: true,
		Path:   "/",
	}
}

// DB is the interface to implement for syncing the configuration parameters.
//
// Syncing is executed every config.SyncInterval. If parameter values are
// changed in the database, the new values get synced to all servers that run
// the application.
type DB interface {

	// Fetch fetches a Config instance from the database.
	Fetch(dst *Config) error

	// Upsert inserts a Config instance into the database if none is present
	// on Configure(). Upsert updates the KeyPairs and TimeStamp values on key
	// rotation time.
	Upsert(src *Config) error
}

// Validate is called to have the application test whether the token data is
// still valid (e.g. to prevent continued access with a token that was created
// with an old password)
//
// 'src' is the authentication data from the token.
//
// 'dst' is the fresh authentication data to replace the token data with.
//
// 'valid' is whether the old data was good enough to keep the current token.
//
// Default implementation always returns the token data as is, and true, which
// is significantly insecure.
//
// Each successful validation stores a timestamp in
// the cookie. Validate is called on Authentication, if the time since the
// validation timestamp > config.SyncInterval
type Validate func(src interface{}) (dst interface{}, valid bool)

var validate = func(src interface{}) (dst interface{}, valid bool) {
	return src, true
}

// Configure configures the package and must be called once before calling any
// other function in this package.
//
// 'record' is an arbitrary (can be empty) instance of the type of the data that
// will be passed to Ligin() to store in the token. It's needed to get its type
// registered with the serialisation package used (encoding/gob).
//
// 'db' is the implementation of the DB interface to sync the configuration
// parameters, or nil, in which case keys will not be rotated.
//
// 'validate' is the function that regularly verifies the token data, or nil,
// which would pose a significant security risk.
//
// 'optionalConfig' is the Config instance to start with, or nil to use the one
// in the db or the default.
//
// For early experiments, use this simplest form:
// 	Configure("", nil, nil)
func Configure(record interface{}, db DB, validateFunc Validate, optionalConfig ...*Config) {
	gob.Register(record)
	gob.Register(time.Now())
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
		if !opt.TimeStamp.IsZero() {
			config.TimeStamp = opt.TimeStamp
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
	dbConfig := new(Config)
	if err := db.Fetch(dbConfig); err != nil {
		// Upload current (default) config to DB if there wasn't any
		db.Upsert(config)
	} else {
		// Replace current config with the one from DB
		config = dbConfig
		// Rotate keys if timed out
		if time.Now().Sub(config.TimeStamp) > config.TimeOut {
			rotateConfig := new(Config)
			*rotateConfig = *config
			rotateConfig.KeyPairs = [][]byte{
				securecookie.GenerateRandomKey(authKeyLen),
				securecookie.GenerateRandomKey(encrKeyLen),
				config.KeyPairs[0],
				config.KeyPairs[1],
			}
			rotateConfig.TimeStamp = time.Now()
			if err := db.Upsert(rotateConfig); err != nil {
				config = rotateConfig
				log.Println("INFO: Security keys rotated")
			}
		}
		configureStore()
	}
}

func getToken(r *http.Request) (session *sessions.Session) {
	session, _ = store.Get(r, tokenName)
	return
}

func create(w http.ResponseWriter, r *http.Request, record interface{}, redirect bool) (err error) {
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

// LogIn creates the token and sets the cookie. It redirects back to the path
// where Authenticate() was called.
//
// 'record' is the authentication data to store in the token, as returned by
// Authentication()
func LogIn(w http.ResponseWriter, r *http.Request, record interface{}) (err error) {
	return create(w, r, record, true)
}

// Update updates the authentication data in the token.
func Update(w http.ResponseWriter, r *http.Request, record interface{}) (err error) {
	return create(w, r, record, false)
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

// Authentication returns the data that was stored in the token on LogIn().
//
// Returns nil if the token is missing, the session has timed out, or the token
// data is invalidated though the Validate function.
//
// When no valid token was present, the request gets redirected to
// config.LogInPath, unless 'optional' is set to 'true'
func Authentication(w http.ResponseWriter, r *http.Request, optional ...bool) (record interface{}) {
	enforce := true
	if len(optional) > 0 {
		enforce = !optional[0]
	}
	session := getToken(r)
	if !session.IsNew && sessionCurrent(session) && accountCurrent(session, w, r) {
		record = session.Values[recordField]
	} else if enforce {
		session = clearToken(r)
		session.Values[returnField] = r.URL.Path
		_ = session.Save(r, w)
		http.Redirect(w, r, config.LogInPath, http.StatusSeeOther)
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

// LogOut deletes the cookie. If 'redirect' is 'true', the request is redirected
// to config.LogOutPath.
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
