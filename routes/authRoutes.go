package routes

import (
	"github.com/ilyesb36/go-auth-api/repositories"
	"github.com/ilyesb36/go-auth-api/controllers"
	"github.com/ilyesb36/go-auth-api/middleware"
	"github.com/gin-gonic/gin"
)

func AuthRoutes(r *gin.Engine, repos *repositories.Repositories) {
	authGroup := r.Group("/fcd03abc-eca5-4cec-99c1-ab79b571e90f")
	{
		authGroup.POST("/register", controllers.Register(repos))
		authGroup.POST("/login", controllers.Login(repos))

		authGroup.POST("/logout", middlewares.AuthMiddleware(repos), controllers.Logout(repos))
		authGroup.POST("/forgot-password", middlewares.AuthMiddleware(repos), controllers.ForgotPassword(repos))
		authGroup.POST("/reset-password", middlewares.AuthMiddleware(repos), controllers.ResetPassword(repos))
	}
}