package middleware

import (
	"net/http"
	"strings"

	"enigmacamp.com/go-jwt/authenticator"
	"github.com/gin-gonic/gin"
)

type authheader struct {
	AuthorizationHeader string `header:"Authorization"`
}
type AuthTokenMiddleware struct {
	acctToken authenticator.Token
}

func NewTokenValidator(accToken authenticator.Token) *AuthTokenMiddleware {
	return &AuthTokenMiddleware{
		acctToken: accToken,
	}
}

func (a *AuthTokenMiddleware) RequireToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/enigma/auth" {
			c.Next()
		} else {
			h := authheader{}
			if err := c.ShouldBindHeader(&h); err != nil {
				c.JSON(401, gin.H{
					"message": "Unauthorized",
				})
				c.Abort()
			}

			tokenString := strings.Replace(h.AuthorizationHeader, "Bearer ", "", -1)
			if tokenString == "" {
				c.JSON(401, gin.H{
					"message": "Unauthorized",
				})
				c.Abort()
				return
			}

			token, err := a.acctToken.VerifyAccessToken(tokenString)
			if err != nil {
				c.JSON(401, gin.H{
					"message": "Unauthorized",
				})
				c.Abort()
				return
			}

			userName, err := a.acctToken.FetchccessToken(token)
			if userName == "" || err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{
					"message": "Unauthorized",
				})
				c.Abort()
				return
			}

			if token != nil {
				c.Set("username", userName)
				c.Next()
			} else {
				c.AbortWithStatusJSON(401, gin.H{"message": "Unauthorized"})
				return
			}

			//if h.AuthorizationHeader == "123" {
			//	c.Next()
			//} else {
			//	c.JSON(401, gin.H{
			//		"message": "Unauthorized",
			//	})
			//	c.Abort()
			//}

		}
	}
}
