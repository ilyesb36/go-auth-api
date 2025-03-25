package routes

import (
	"database/sql"
	"github.com/ilyesb36/go-auth-api/controllers"
	"github.com/ilyesb36/go-auth-api/middleware"
	"github.com/gin-gonic/gin"
)

func AuthRoutes(r *gin.Engine, db *sql.DB) {
	authGroup := r.Group("/fcd03abc-eca5-4cec-99c1-ab79b571e90f")
	{
		authGroup.POST("/register", controllers.Register(db))
		authGroup.POST("/login", controllers.Login(db))

		authGroup.POST("/logout", middlewares.AuthMiddleware(db), controllers.Logout(db))
		authGroup.POST("/forgot-password", controllers.ForgotPassword(db))
		authGroup.POST("/reset-password", controllers.ResetPassword(db))
	}
}