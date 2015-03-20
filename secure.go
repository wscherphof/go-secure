package secure

import (
  "crypto/hmac"
  "crypto/sha256"
  "time"
  "encoding/json"
  "encoding/base64"
  "net/http"
)

func serialise (src interface{}) []byte {
  b, err := json.Marshal(src)
  if err != nil {
    panic(err)
  }
  return b
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

// TODO: make configurable
// Idea for defining & updating the key:
// - store it in DB, incl. time stamp
// - continuously update it in the DB, incl. time stamp
//   - but only if it wasn't update recently by another server
//   - also check for an update by a peer server
// - use the new key for new sessions
// - keep the old key to try if old sessions fail on the new key
// - ditch the old key on the next update; no more than 2 key alternatives
// - use a key update interval longer than the session TimeOut duration
const Key = "qwerty"
const RedirectPath = "/login"
const TimeOut = 15 * 60 // seconds

func MAC (message []byte) []byte {
  mac := hmac.New(sha256.New, []byte(Key))
  mac.Write(message)
  return mac.Sum(nil)
}

type Session struct{
  UID string
  Time time.Time
}

type Token struct{
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
    MAC(session),
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
    eq := hmac.Equal(token.MAC, MAC(token.Session))
    if eq {
      var session Session
      deserialise(token.Session, &session)
      // Verify the session hasn't timed out
      since := time.Since(session.Time).Seconds()
      if since < TimeOut {
        // Update the Token cookie to include the current time
        Update(w, session.UID)
        return session.UID
      }
    }
  }
  http.Redirect(w, r, RedirectPath + "?return=" + r.URL.Path, 302)
  return ""
}
