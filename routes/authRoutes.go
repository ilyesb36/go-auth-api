package routes

import (
	"github.com/ilyesb36/go-auth-api/controllers"

	"github.com/gin-gonic/gin"
)

func AuthRoutes(r *gin.Engine) {
	authGroup := r.Group("/fcd03abc-eca5-4cec-99c1-ab79b571e90f/auth")
	{
		authGroup.POST("/register", controllers.Register)
		authGroup.POST("/login", controllers.Login)
	}
}
