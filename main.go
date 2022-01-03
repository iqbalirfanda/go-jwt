package main

import (
	"fmt"
	"log"
	"net/http"

	"time"

	"enigmacamp.com/go-jwt/authenticator"
	"enigmacamp.com/go-jwt/delivery/middleware"
	"enigmacamp.com/go-jwt/model"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt"
)

func main() {
	r := gin.Default()
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   0,
	})

	takenConfig := authenticator.TokenConfig{
		ApplicationName:     "ENIGMA",
		JwtSigningMethod:    jwt.SigningMethodHS256,
		JwtSignatureKey:     "P@ssw0rd",
		AccessTokenLifeTime: 120 * time.Second,
		Client:              client,
	}
	tokenService := authenticator.NewTokenService(takenConfig)
	r.Use(middleware.NewTokenValidator(tokenService).RequireToken())

	publicRoute := r.Group("/enigma")
	publicRoute.POST("/auth", func(c *gin.Context) {
		var user model.Credential
		if err := c.BindJSON(&user); err != nil {
			c.JSON(400, gin.H{
				"message": "Can't bind Struct",
			})
			return
		}

		if user.Username == "enigma" && user.Password == "123" {
			token, err := tokenService.CreateAccessToken(&user)
			fmt.Println(err)
			if err != nil {
				c.AbortWithStatus(500)
				return
			}

			err = tokenService.StoreAccessToken(user.Username, token)
			if err != nil {
				fmt.Println(err)
				c.AbortWithStatus(401)

				return
			}

			c.JSON(http.StatusOK, gin.H{
				"token": token,
			})
		} else {
			c.AbortWithStatus(401)
		}
	})

	publicRoute.GET("/user", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": c.GetString("username"),
		})
	})

	publicRoute.GET("/logout", func(c *gin.Context) {
		log.Println("request for logout")
		c.JSON(200, gin.H{
			"message": "berhasil logout",
		})
	})

	publicRoute.GET("/exit", func(c *gin.Context) {
		log.Println("request for exit")
		c.JSON(200, gin.H{
			"message": "berhasil exit",
		})
	})

	err := r.Run("localhost:8888")
	if err != nil {
		panic(err)
	}
}
