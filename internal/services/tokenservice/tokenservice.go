package tokenservice

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt"
)

const (
	accessExpiresAt   = 1
	refreshsExpiresAt = 24 * 10
)

type UserClaims struct {
	Id    int    `json:"id"`
	First string `json:"first_name"`
	Last  string `json:"second_name"`
	Email string `json:"email"`
	jwt.StandardClaims
}

func NewUserClaims(id int, first string, last string, email string) *UserClaims {
	return &UserClaims{
		Id:    id,
		First: first,
		Last:  last,
		Email: email,
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Hour * accessExpiresAt).Unix(),
		},
	}
}

func NewStandartClaims() *jwt.StandardClaims {
	return &jwt.StandardClaims{
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour * refreshsExpiresAt).Unix(),
	}
}

func NewAccessToken(claims UserClaims) (string, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return accessToken.SignedString([]byte(os.Getenv("TOKEN_SECRET")))
}

func NewRefreshToken(claims jwt.StandardClaims) (string, error) {
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return refreshToken.SignedString([]byte(os.Getenv("TOKEN_SECRET")))
}

func ParseAccessToken(accessToken string) (*UserClaims, error) {
	parsedAccessToken, err := jwt.ParseWithClaims(accessToken, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("TOKEN_SECRET")), nil
	})

	if err != nil {
		return nil, err
	}

	return parsedAccessToken.Claims.(*UserClaims), nil
}

func ParseRefreshToken(refreshToken string) (*jwt.StandardClaims, error) {
	parsedRefreshToken, err := jwt.ParseWithClaims(refreshToken, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("TOKEN_SECRET")), nil
	})

	if err != nil {
		return nil, err
	}

	return parsedRefreshToken.Claims.(*jwt.StandardClaims), nil
}
