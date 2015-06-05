/*
Package secure manages client side session tokens for stateless web applications.

Tokens are stored as an http cookie. An encrypted connection (https) is required.
Call Configuere() once to provide the information for the package to operate,
including the type of data that will be stored in the token.

The actual configuration parameters are stored in a Config type struct,
that can be synced with an external database, through the DB interface.

Once configured, the application can call Authentication() to retrieve the
data from the token; if that's nil, call Challenge() to redirect to a login page.
If the challenge is fullfilled, call LogIn to create a new token. To delete the
token, call LogOut().

The secure/middleware package for github.com/julienschmidt/httprouter a
SecureHandle to enforce a valid session for a specific application route, and
an IfSecureHandle to provide separate handle alternatives for requests with
or without a valid token.

So you could have:
	import (
		"github.com/julienschmidt/httprouter"
		"github.com/wscherphof/secure"
		middleware "github.com/wscherphof/secure/httprouter"
		"net/http"
	)
	router.GET("/", middleware.IfSecureHandle(HomeLoggedIn, HomeLoggedOut))
	router.POST("/orders", middleware.SecureHandle(NewOrder))

	func NewOrder(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		auth := secure.Authentication(w, r)
		...
	}

You'll probably want to wrap Authentication() in a function that converts the
interface{} result to the type that you use for the token data.
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

	// ErrNoTLS is returned by LogIn() if the connection isn't encrypted (https)
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

	// LogInPath is the URL where Challenge() redirects to.
	// Default value is "/session".
	LogInPath string

	// LogOutPath is the URL where LogOut() redirects to.
	// Default value is "/".
	LogOutPath string

	// TimeOut is when a token expires (time after LogIn())
	// Default value is 6 * 30 days.
	TimeOut time.Duration

	// SyncInterval is how often the configurations is synced with an external
	// database, and how often the token data is offered to the application
	// to revalidate through the Validate function.
	// Default value is 5 minutes.
	SyncInterval time.Duration

	// KeyPairs are 4 32-long byte arrays (two pairs of an authentication
	// key and an encryption key); the 2nd pair is used for key rotation.
	// Default value is newly generated keys.
	// Keys get rotated on the first sync cycle after a TimeOut interval -
	// new tokens use the new keys; existing tokens continue to use the old keys.
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
	Fetch() *Config

	// Upsert inserts a Config instance into the database if none is present
	// on Configure(). Upsert updates the KeyPairs and TimeStamp values on key
	// rotation time.
	Upsert(*Config)
}

// Validate is used every SyncInterval to have the application test whether
// the token data is still valid (e.g. to prevent continued access with a token
// that was created with an old password)
//
// src is the data from the token.
//
// dst is the fresh data to replace the token data.
//
// valid is whether the old data was good enough to keep the token.
//
// Default implementation always returns the token data as is, and true.
type Validate func(src interface{}) (dst interface{}, valid bool)

var validate = func(src interface{}) (dst interface{}, valid bool) {
	return src, true
}

// Configure configures the package and must be called once before use.
//
// record is an arbitrary (can be empty) instance of the type of the data to be
// stored in the token. It's needed to get registered in the serialisation
// package used (encoding/gob).
//
// db is the DB implementation to sync the configuration parameters, or nil, in
// which case keys will not be rotated.
//
// validate is the function that regularly verifies the token data, or nil, which
// would pose a significant security risk.
//
// optionalConfig is the Config instance to start with, or nil to use the one in
// the db or the default.
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

// LogIn creates the token and sets the cookie.
//
// record is the data to store in the token, as returned by Authentication()
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

// Authentication returns the data that was stored in the token by LogIn().
//
// Returns nil if the token is missing, the session has timed out, or the token
// data is no longer valid according to the Validate function.
// Every config.SyncInterval, the token data is refreshed through the Validate
// function.
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

// Challenge clears the token data and redirects to config.LogInPath.
func Challenge(w http.ResponseWriter, r *http.Request) {
	session := clearToken(r)
	session.Values[returnField] = r.URL.Path
	_ = session.Save(r, w)
	http.Redirect(w, r, config.LogInPath, http.StatusSeeOther)
}

// LogOut deletes the cookie and redirects to config.LogOutPath.
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
