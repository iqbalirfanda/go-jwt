package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	fmt.Println(r)

	type authheader struct {
		AuthorizationHeader string `header:"Authorization"`
	}

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
