package token_jwt

import (
	"fmt"
	"time"

	"github.com/chefsgo/token"
	"github.com/dgrijalva/jwt-go"
)

type (
	jwtDriver  struct{}
	jwtConnect struct {
		config  token.Config
		setting jwtSetting
	}
	jwtSetting struct {
		Expiry time.Duration
	}
)

//连接
func (driver *jwtDriver) Connect(config token.Config) (token.Connect, error) {
	setting := jwtSetting{}
	return &jwtConnect{
		config: config, setting: setting,
	}, nil
}

//打开连接
func (connect *jwtConnect) Open() error {
	return nil
}

//关闭连接
func (connect *jwtConnect) Close() error {
	return nil
}

//签名
func (connect *jwtConnect) Sign(data *token.Token) (string, error) {
	if data.Expiry < 0 {
		data.Expiry = 0
	}

	claims := &jwtClaims{
		Token: data,
	}

	//采用HMAC SHA256加密算法
	signer := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := signer.SignedString([]byte(connect.config.Secret))
	if err != nil {
		return "", err
	}

	return token, nil
}

//验签
func (connect *jwtConnect) Validate(str string) (*token.Token, error) {
	token, err := jwt.ParseWithClaims(str, &jwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(connect.config.Secret), nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*jwtClaims); ok && token.Valid {
		//过期已经不做为强制验证了，只是做为是否登录的依据，信息还是要留着返回
		if claims.Token.Authorized {
			//auth=true的时候，才处理available
			//要不然，只要token不过期，就永远auth=true了，
			claims.Token.Authorized = claims.available
		}

		return claims.Token, nil
	} else {
		return nil, err
	}
}
