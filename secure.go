package secure

import (
  "crypto/hmac"
  "crypto/sha256"
  "time"
  "encoding/json"
  "encoding/base64"
  "net/http"
  "log"
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

type DB interface {
  Fetch() Config
}

func Init (db DB) {
  go func () {
    for {
      // TODO:
      // - use the new key for new sessions
      // - keep the old key to try if old sessions fail on the new key
      // - ditch the old key on the next update; no more than 2 key alternatives
      config = db.Fetch()
      log.Print("INFO: fetched Secure config")
      time.Sleep(config.TimeOut)
    }
  }()
}

func serialise (src interface{}) []byte {
  b, err := json.Marshal(src)
  if err != nil {
    panic(err)
  }
  return b
}

type Session struct {
  UID string
  Time time.Time
}

type Token struct {
  Session []byte
  MAC []byte
}

func LogIn (w http.ResponseWriter, uid string) {
  session := serialise(Session{
    uid,
    time.Now(),
  })
  token := serialise(Token{
    session,
    mac(session),
  })
  http.SetCookie(w, &http.Cookie{
    Name: "Token",
    Value: string(encode(token)),
    Path: "/",
  })
}

func Update (w http.ResponseWriter, uid string) {
  LogIn(w, uid)
}

func Authenticate (w http.ResponseWriter, r *http.Request) string {
  if cookie, err := r.Cookie("Token"); err == nil {
    var token Token
    deserialise(decode([]byte(cookie.Value)), &token)
    // Compare the given MAC with what we would've generated
    eq := hmac.Equal(token.MAC, mac(token.Session))
    if eq {
      var session Session
      deserialise(token.Session, &session)
      // Verify the session hasn't timed out
      since := time.Since(session.Time)
      if since < config.TimeOut {
        // Update the Token cookie to include the current time
        Update(w, session.UID)
        return session.UID
      }
    }
  }
  http.Redirect(w, r, config.RedirectPath + "?return=" + r.URL.Path, 302)
  return ""
}

func mac (message []byte) []byte {
  m := hmac.New(sha256.New, []byte(config.Secret.Key))
  m.Write(message)
  return m.Sum(nil)
}

func deserialise (src []byte, dst interface{}) {
  err := json.Unmarshal(src, dst)
  if err != nil {
    panic(err)
  }
}

func encode (value []byte) []byte {
  encoded := make([]byte, base64.URLEncoding.EncodedLen(len(value)))
  base64.URLEncoding.Encode(encoded, value)
  return encoded
}

func decode (value []byte) []byte {
  decoded := make([]byte, base64.URLEncoding.DecodedLen(len(value)))
  b, err := base64.URLEncoding.Decode(decoded, value)
  if err != nil {
    panic(err)
  }
  return decoded[:b]
}
