package token_jwt

import (
	"github.com/chefsgo/token"
)

func Driver() token.Driver {
	return &jwtDriver{}
}

func init() {
	token.Register("jwt", Driver())
}
