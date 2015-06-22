package secure

import (
	"encoding/gob"
	"github.com/gorilla/securecookie"
)

type RequestToken string

const requestTokenName = "4f3a0292-59c5-488a-b3fb-6e503c929331"

func RegisterRequestTokenData(data interface{}) {
	gob.Register(data)
}

func NewRequestToken(data interface{}) (token RequestToken, err error) {
	t, e := securecookie.EncodeMulti(requestTokenName, data, requestTokenCodecs...)
	return RequestToken(t), e
}

func (r RequestToken) Read(dst interface{}) (err error) {
	return securecookie.DecodeMulti(requestTokenName, string(r), dst, requestTokenCodecs...)
}
