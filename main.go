package main

import (
	"github.com/gin-gonic/gin"
	"github.com/ilyesb36/go-auth-api/routes"
)

func main() {
	r := gin.Default()

	r.GET("/fcd03abc-eca5-4cec-99c1-ab79b571e90f/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	routes.AuthRoutes(r)

	r.Run(":8080")
}
