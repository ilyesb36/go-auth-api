package controllers

import (
	"database/sql"
	"net/http"
	"time"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/ilyesb36/go-auth-api/config"
	"github.com/ilyesb36/go-auth-api/models"
	"github.com/ilyesb36/go-auth-api/utils"
)

func Register(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var user models.User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		exists, err := config.EmailExists(db, user.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur lors de la verification de l'email"})
			return
		}
		if exists == true {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email déjà utilisé"})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur lors du hachage du mot de passe"})
			return
		}
		user.Password = string(hashedPassword)

		_, err = config.InsertUser(db, &user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"message": "Inscription réussie"})
	}
}

func Login(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var loginData struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		if err := c.ShouldBindJSON(&loginData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		user, err := config.GetUserByEmail(db, loginData.Email)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Mot de passe incorrect"})
			return
		}

		expirationTime := time.Now().Add(time.Hour)
		claims := &jwt.RegisteredClaims{
			Issuer:    user.Email,
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(config.GetEnv("JWT_SECRET", "secret")))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur lors de la création du token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	}
}

func Logout(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		email, timestamp, err := utils.ExtractEmailAndExpFromJWT(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Erreur lors de l'extraction de l'expiration"})
			log.Fatal("Erreur lors de l'invalidation du token :", err)
		}
		userID, err := config.GetUserIDByEmail(db, email)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Erreur lors de la recuperation de l'ID"})
			log.Fatal("Erreur lors de la recuperation de l'ID :", err)
		}
		expiresAt := time.Unix(timestamp, 0)

		_, err = config.InsertToken(db, userID, token, expiresAt)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Erreur lors de la deconnexion"})
			log.Fatal("Erreur lors de l'invalidation du token :", err)
		}
		c.JSON(http.StatusOK, gin.H{"message": "Session terminée"})
	}
}

func ForgotPassword(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var request struct {
			Email string `json:"email"`
		}

		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Format invalide"})
			return
		}

		user, err := config.GetUserByEmail(db, request.Email)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		token, err := utils.GenerateResetToken(user.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur lors de la génération du token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Token généré", "reset_token": token})
	}
}

func ResetPassword(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var request struct {
			Token       string `json:"token"`
			NewPassword string `json:"new_password"`
		}

		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Format invalide"})
			return
		}

		claims, err := utils.VerifyResetToken(request.Token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token invalide ou expiré"})
			return
		}
		
		user, err := config.GetUserByEmail(db, claims.Issuer)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur lors du hachage du mot de passe"})
			return
		}
		user.Password = string(hashedPassword)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Erreur lors de la recuperation de l'ID"})
			log.Fatal("Erreur lors de la recuperation de l'ID :", err)
		}
		err = config.UpdatePassword(db, user.ID, user.Password)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Erreur lors de la mise à jour du mot de passe"})
			log.Fatal("Erreur lors de la mise à jour du mot de passe :", err)
		}
		c.JSON(http.StatusOK, gin.H{"message": "Mot de passe réinitialisé avec succès"})
	}
}
