package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

type authheader struct {
	AuthorizationHeader string `header:"Authorization"`
}

type Credential struct {
	Username string `json:"username"`
	Password string `json:"paassword"`
}

func main() {
	r := gin.Default()
	fmt.Println(r)

	r.POST("/login", func(c *gin.Context) {
		var user Credential
		if err := c.BindJSON(&user); err != nil {
			c.JSON(400, gin.H{
				"message": "can't bind struct",
			})
			return
		}

		if user.Username == "enigma" && user.Password == "123" {
			c.JSON(200, gin.H{
				"token": "123",
			})
		}
	})

	r.GET("/customer", func(c *gin.Context) {
		h := authheader{}
		if err := c.ShouldBindHeader(&h); err != nil {
			c.JSON(401, gin.H{
				"message": "Unathorized",
			})
			return
		}

		if h.AuthorizationHeader == "123" {
			c.JSON(200, gin.H{
				"message": "customer",
			})
			return
		}
		c.JSON(401, gin.H{
			"message": "Unauthorized",
		})
	})

	err := r.Run("localhost:8888")
	if err != nil {
		fmt.Println(err)
	}
}
