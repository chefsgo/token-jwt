package token_jwt

import (
	"github.com/chefsgo/chef"
)

func Driver() chef.TokenDriver {
	return &jwtTokenDriver{}
}

func init() {
	chef.Register("jwt", Driver())
}
