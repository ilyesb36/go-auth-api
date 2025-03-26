package middlewares

import (
	"net/http"
	"strings"
	"github.com/gin-gonic/gin"
	"github.com/ilyesb36/go-auth-api/utils"
)

func ResetTokenMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token de réinitialisation manquant"})
			c.Abort()
			return
		}
		claims, err := utils.VerifyResetToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token de réinitialisation invalide ou expiré"})
			c.Abort()
			return
		}
		c.Set("reset_email", claims.Issuer)
		c.Next()
	}
}