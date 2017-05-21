/*
Package secure manages authentication cookies for stateless web applications,
and form tokens for CSRF protection.

An encrypted connection (https) is required.

Call 'Configure()' once to provide the information for the package to operate,
including the type of the authentication data that will be used. The actual
configuration parameters are stored in a 'Config' type struct. The 'DB'
interface syncs the Config to an external database, and automatically rotates
security keys.

Once configured, call 'Authentication()' to retrieve the data from the cookie.
It will redirect to a login page if no valid cookie is present (unless the
'optional' argument was 'true'). 'LogIn()' creates a new cookie, stores the
provided data in it, and redirects back to the page that required the
authentication.
'Update()' updates the authentication data in the current cookie. 'LogOut()'
deletes the cookie.

You'll probably want to wrap 'Authentication()' in a function that converts the
'interface{}' result to the type that you use for the cookie data.
*/
package secure

import (
	"encoding/gob"
	"errors"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"log"
	"time"
)

var (

	// ErrTokenNotSaved is returned by LogIn() if it couldn't set the cookie.
	ErrTokenNotSaved = errors.New("secure: failed to save the session cookie")

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

	// CookieTimeOut is when a cookie expires (time after LogIn())
	// Default value is 6 * 30 days.
	CookieTimeOut time.Duration

	// ValidateTimeOut determines whether it's time to have the
	// cookie data checked by the ValidateCookie function.
	// Default value is 5 minutes.
	ValidateTimeOut time.Duration

	// CookieKeyPairs are 4 32-long byte arrays (two pairs of an authentication key
	// and an encryption key); the 2nd pair is used for key rotation.
	// Default value is newly generated keys.
	// Keys get rotated on the first sync cycle after a CookieTimeOut interval -
	// new cookies use the new keys; existing cookies continue to use the old
	// keys.
	CookieKeyPairs [][]byte

	// CookieTimeStamp is when the latest cookie key pair was generated.
	CookieTimeStamp time.Time

	FormTokenKeys *Keys
}

var config = &Config{
	LogInPath:     "/session",
	LogOutPath:    "/",
	CookieTimeOut: 6 * 30 * 24 * time.Hour,
	ValidateTimeOut:  5 * time.Minute,
	CookieKeyPairs: [][]byte{
		securecookie.GenerateRandomKey(authKeyLen),
		securecookie.GenerateRandomKey(encrKeyLen),
		securecookie.GenerateRandomKey(authKeyLen),
		securecookie.GenerateRandomKey(encrKeyLen),
		securecookie.GenerateRandomKey(authKeyLen),
		securecookie.GenerateRandomKey(encrKeyLen),
	},
	CookieTimeStamp: time.Now(),
	FormTokenKeys: &Keys{
		KeyPairs: [][]byte{
			securecookie.GenerateRandomKey(authKeyLen),
			securecookie.GenerateRandomKey(encrKeyLen),
			securecookie.GenerateRandomKey(authKeyLen),
			securecookie.GenerateRandomKey(encrKeyLen),
			securecookie.GenerateRandomKey(authKeyLen),
			securecookie.GenerateRandomKey(encrKeyLen),
		},
		Start: time.Now(),
		TimeOut: 5 * time.Minute,
	},
}

var (
	store           *sessions.CookieStore
	formTokenCodecs []securecookie.Codec
)

// DB is the interface to implement for syncing the configuration parameters.
//
// Syncing is executed every config.SyncInterval. If parameter values are
// changed in the database, the new values get synced to all servers that run
// the application.
type DB interface {

	// Fetch fetches a Config instance from the database.
	Fetch(dst *Config) error

	// Upsert inserts a Config instance into the database if none is present
	// on Configure(). Upsert updates the CookieKeyPairs and CookieTimeStamp values on key
	// rotation time.
	Upsert(src *Config) error
}

// ValidateCookie is the type of the function passed to Configure(), that gets called
// to have the application test whether the cookie data is still valid (e.g. to
// prevent continued access with a cookie that was created with an old password)
//
// 'src' is the authentication data from the cookie.
//
// 'dst' is the fresh authentication data to replace the cookie data with.
//
// 'valid' is whether the old data was good enough to keep the current cookie.
//
// Default implementation always returns the cookie data as is, and true, which
// is significantly insecure.
//
// Each successful validation stores a timestamp in
// the cookie. ValidateCookie is called on Authentication, if the time since the
// validation timestamp > config.SyncInterval
type ValidateCookie func(src interface{}) (dst interface{}, valid bool)

var (
	db       DB
	validate ValidateCookie
)

// Configure configures the package and must be called once before calling any
// other function in this package.
//
// 'record' is an arbitrary (can be empty) instance of the type of the
// authentication data that will be passed to Login() to store in the cookie.
// It's needed to get its type registered with the serialisation package used
// (encoding/gob).
//
// 'dbImpl' is the implementation of the DB interface to sync the configuration
// and rotate the keys.
//
// 'validate' is the function that regularly verifies the cookie data.
//
// 'optionalConfig' is the Config instance to start with. If omitted, the config
// from the db or the default config is used.
func Configure(record interface{}, dbImpl DB, validateFunc ValidateCookie, optionalConfig ...*Config) {
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
		if opt.CookieTimeOut > 0 {
			config.CookieTimeOut = opt.CookieTimeOut
		}
		if opt.ValidateTimeOut > 0 {
			config.ValidateTimeOut = opt.ValidateTimeOut
		}
		if len(opt.CookieKeyPairs) == 4 {
			config.CookieKeyPairs = opt.CookieKeyPairs
		}
		if !opt.CookieTimeStamp.IsZero() {
			config.CookieTimeStamp = opt.CookieTimeStamp
		}
		if opt.FormTokenKeys != nil {
			config.FormTokenKeys = opt.FormTokenKeys
		}
	}
	db = dbImpl
	validate = validateFunc
	setKeys()
	go func() {
		syncFormToken()
		time.Sleep(config.FormTokenKeys.TimeOut / 2)
		for {
			syncFormToken()
			time.Sleep(config.FormTokenKeys.TimeOut)
		}
	}()
}

type Keys struct {
	KeyPairs [][]byte
	Start time.Time
	TimeOut time.Duration
	codecs []securecookie.Codec
}

func (k *Keys) Stale() bool {
	return time.Since(k.Start) >= k.TimeOut
}

func (k *Keys) Rotate() (ret *Keys) {
	ret = &Keys {
		KeyPairs: [][]byte{
			k.KeyPairs[4],
			k.KeyPairs[5],
			k.KeyPairs[0],
			k.KeyPairs[1],
			securecookie.GenerateRandomKey(authKeyLen),
			securecookie.GenerateRandomKey(encrKeyLen),
		},
		TimeOut: k.TimeOut,
		Start: time.Now(),
	}
	return ret
}

func (k *Keys) Codecs() []securecookie.Codec {
	if len(k.codecs) == 0 {
		k.codecs = securecookie.CodecsFromPairs(k.KeyPairs...)
	}
	return k.codecs
}

func (k *Keys) Encode(name string, value interface{}) (s string) {
	if k.Stale() {
		*k = *k.Rotate()
		go syncFormToken()
	}
	var err error
	if s, err = securecookie.EncodeMulti(name, value, k.Codecs()...); err != nil {
		log.Panicln("ERROR: encoding form token failed", err)
	}
	return
}

func (k *Keys) Decode(name string, value string, dst interface{}) error {
	return securecookie.DecodeMulti(name, value, dst, k.Codecs()...)
}

func syncFormToken() {
	dbConfig := new(Config)
	if err := db.Fetch(dbConfig); err != nil {
		// Upload current (default) config to DB if there wasn't any
		db.Upsert(config)
	} else {
		// Replace current config with the one from DB
		config = dbConfig
		// Rotate FormToken keys if timed out
		if config.FormTokenKeys.Stale() {
			rotateConfig := new(Config)
			*rotateConfig = *config
			rotateConfig.FormTokenKeys = config.FormTokenKeys.Rotate()
			if err := db.Upsert(rotateConfig); err == nil {
				config = rotateConfig
				log.Println("INFO: FormToken keys rotated")
			}
		}
	}
}

func setKeys() {
	store = sessions.NewCookieStore(config.CookieKeyPairs...)
	store.Options = &sessions.Options{
		MaxAge: int(config.CookieTimeOut / time.Second),
		Secure: true,
		Path:   "/",
	}
}
