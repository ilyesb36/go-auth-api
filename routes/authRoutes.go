package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/ilyesb36/go-auth-api/controllers"
	middlewares "github.com/ilyesb36/go-auth-api/middleware"
	"github.com/ilyesb36/go-auth-api/repositories"
)

func AuthRoutes(r *gin.Engine, repos *repositories.Repositories) {
	authGroup := r.Group("/fcd03abc-eca5-4cec-99c1-ab79b571e90f")
	{
		authGroup.POST("/register", controllers.Register(repos))
		authGroup.POST("/login", controllers.Login(repos))

		authGroup.POST("/logout", controllers.Logout(repos))
		authGroup.POST("/forgot-password", controllers.ForgotPassword(repos))
		authGroup.GET("/me", middlewares.AuthMiddleware(repos), controllers.Me(repos))
		authGroup.POST("/reset-password", controllers.ResetPassword(repos))
		authGroup.POST("/refresh-token", controllers.RefreshToken(repos))
	}
}
