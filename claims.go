package token_jwt

import (
	"errors"
	"time"

	"github.com/chefsgo/token"
)

var (
	errorExpired = errors.New("expired token")
)

type (
	jwtClaims struct {
		available bool
		Token     *token.Token
	}
)

func (c *jwtClaims) Valid() error {
	now := time.Now().Unix()

	c.available = true

	//注意，就算过期了，也依旧返回正常，通用
	//只是Expired标识为true
	if c.Token.Expiry > 0 {
		if c.Token.Expiry <= now {
			c.available = false
			//return errorExpired
		}
	}

	//待优化，如果token被block，也应该设置为不可用

	return nil
}
