package tokenservice

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt"
)

const (
	accessExpiresAt  = 1
	refreshExpiresAt = 24 * 10
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
		ExpiresAt: time.Now().Add(time.Hour * refreshExpiresAt).Unix(),
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

func GetUserClaimsFromAccessToken(accessToken string) (*UserClaims, error) {
	parsedAccessToken, err := jwt.ParseWithClaims(accessToken, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("TOKEN_SECRET")), nil
	})

	return parsedAccessToken.Claims.(*UserClaims), err
}

func ParseAccessToken(accessToken string) (*UserClaims, error) {
	parsedAccessToken, err := jwt.ParseWithClaims(accessToken, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("TOKEN_SECRET")), nil
	})

	if claims, ok := parsedAccessToken.Claims.(*UserClaims); ok && parsedAccessToken.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}

func ValidateRefreshToken(tokenString string) (*jwt.StandardClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("TOKEN_SECRET")), nil
	})

	if claims, ok := token.Claims.(*jwt.StandardClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}
