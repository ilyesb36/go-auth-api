package main

import (
	"github.com/gin-gonic/gin"
	"github.com/ilyesb36/go-auth-api/routes"
	"github.com/ilyesb36/go-auth-api/config"
	"github.com/ilyesb36/go-auth-api/repositories"
)

func main() {
	r := gin.Default()

	r.GET("/fcd03abc-eca5-4cec-99c1-ab79b571e90f/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	config.ApplyMigrations()

	db := config.ConnectDB()
	defer db.Close()

	repos := repositories.NewRepositories(db)

	routes.AuthRoutes(r, repos)

	err := r.Run(":8080")
	if err != nil {
		panic(err)
	}
}
