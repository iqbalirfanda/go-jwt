package authenticator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"enigmacamp.com/go-jwt/model"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

type Token interface {
	CreateAccessToken(cred *model.Credential) (*TokenDetails, error)
	VerifyAccessToken(tokenString string) (*AccessDetails, error)
	StoreAccessToken(userName string, TokenDetails *TokenDetails) error
	FetchccessToken(AccessDetails *AccessDetails) (string, error)
}

type token struct {
	Config TokenConfig
}

type TokenConfig struct {
	ApplicationName     string
	JwtSignatureKey     string
	JwtSigningMethod    *jwt.SigningMethodHMAC
	AccessTokenLifeTime time.Duration
	Client              *redis.Client
}

type TokenDetails struct {
	AccessToken string
	AccessUuid  string
	AtExpires   int64
}

type AccessDetails struct {
	AccessUuid string
	UserName   string
}

func NewTokenService(config TokenConfig) Token {
	return &token{
		Config: config,
	}
}

func (t *token) CreateAccessToken(cred *model.Credential) (*TokenDetails, error) {
	td := &TokenDetails{}
	now := time.Now().UTC()
	end := now.Add(t.Config.AccessTokenLifeTime)

	td.AtExpires = end.Unix()
	td.AccessUuid = uuid.New().String()

	claims := MyClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer: t.Config.ApplicationName,
		},
		Username:   cred.Username,
		Email:      cred.Email,
		AccessUUID: td.AccessUuid,
	}

	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = end.Unix()

	token := jwt.NewWithClaims(t.Config.JwtSigningMethod, claims)
	newToken, err := token.SignedString([]byte(t.Config.JwtSignatureKey))
	td.AccessToken = newToken
	if err != nil {
		return nil, err
	}
	return td, nil
}

func (t *token) VerifyAccessToken(tokenString string) (*AccessDetails, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Signing method invalid")
		} else if method != t.Config.JwtSigningMethod {
			return nil, fmt.Errorf("Signing method invalid")
		}

		return []byte(t.Config.JwtSignatureKey), nil
	})

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, err
	}
	return nil, err

	accessUUID := claims["AccessUUID"].(string)
	username := claims["Username"].(string)
	return &AccessDetails{
		AccessUuid: accessUUID,
		UserName:   username,
	}, nil
}

func (t *token) StoreAccessToken(userName string, TokenDetails *TokenDetails) error {
	at := time.Unix(TokenDetails.AtExpires, 0)
	now := time.Now()
	err := t.Config.Client.Set(context.Background(), TokenDetails.AccessUuid, userName, at.Sub(now)).Err()
	if err != nil {
		return err
	}
	return nil
}

func (t *token) FetchccessToken(AccessDetails *AccessDetails) (string, error) {
	if AccessDetails != nil {
		userName, err := t.Config.Client.Get(context.Background(), AccessDetails.AccessUuid).Result()
		if err != nil {
			return "", nil
		}
		return userName, nil
	} else {
		return "", errors.New("invalid access")
	}
}
