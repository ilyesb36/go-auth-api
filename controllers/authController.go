package controllers

import (
	"net/http"
	"time"
	"log"
	"os"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/ilyesb36/go-auth-api/models"
	"github.com/ilyesb36/go-auth-api/repositories"
	"github.com/ilyesb36/go-auth-api/utils"
)

func Register(repos *repositories.Repositories) gin.HandlerFunc {
	return func(c *gin.Context) {
		var user models.User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		exists, err := repos.UserRepository.EmailExists(user.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur lors de la verification de l'email"})
			return
		}
		if exists {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email déjà utilisé"})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur lors du hachage du mot de passe"})
			return
		}
		user.Password = string(hashedPassword)

		_, err = repos.UserRepository.InsertUser(&user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"message": "Inscription réussie"})
	}
}

func Login(repos *repositories.Repositories) gin.HandlerFunc {
	return func(c *gin.Context) {
		var loginData struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		if err := c.ShouldBindJSON(&loginData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		user, err := repos.UserRepository.GetUserByEmail(loginData.Email)
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
		tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur lors de la création du token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	}
}

func Logout(repos *repositories.Repositories) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		email, timestamp, err := utils.ExtractEmailAndExpFromJWT(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Erreur lors de l'extraction de l'expiration"})
			log.Fatal("Erreur lors de l'invalidation du token :", err)
		}
		userID, err := repos.UserRepository.GetUserIDByEmail(email)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Erreur lors de la recuperation de l'ID"})
			log.Fatal("Erreur lors de la recuperation de l'ID :", err)
		}
		expiresAt := time.Unix(timestamp, 0)

		expiredToken := &models.Expired{
			UserID:    userID,
			Token:     token,
			ExpiresAt: expiresAt,
		}
		_, err = repos.TokenRepository.InsertToken(expiredToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Erreur lors de la deconnexion"})
			log.Fatal("Erreur lors de l'invalidation du token :", err)
		}
		c.JSON(http.StatusOK, gin.H{"message": "Session terminée"})
	}
}
func ForgotPassword(repos *repositories.Repositories) gin.HandlerFunc {
	return func(c *gin.Context) {
		var request struct {
			Email string `json:"email"`
		}

		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Format invalide"})
			return
		}


		// Toujours renvoyer un message générique pour ne pas révéler si l'email est valide
		user, err := repos.UserRepository.GetUserByEmail(request.Email)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"message": "Un code a été envoyé à votre adresse mail"})
			return
		}

		code := fmt.Sprintf("%06d", rand.Intn(1000000))
		expiresAt := time.Now().Add(5 * time.Minute)
		err = repos.ResetCodeRepository.InsertResetCode(user.Email, code, expiresAt)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur enregistrement code"})
			return
		}
		_ = utils.SendResetCodeEmail(user.Email, code)

		c.JSON(http.StatusOK, gin.H{"message": "Un code a été envoyé à votre adresse mail"})
	}
}

func ResetPassword(repos *repositories.Repositories) gin.HandlerFunc {
	return func(c *gin.Context) {
		var request struct {
			Email       string `json:"email"`
			Code        string `json:"code"`
			NewPassword string `json:"new_password"`
		}

		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Format invalide"})
			return
		}

		valid, err := repos.ResetCodeRepository.VerifyResetCode(request.Email, request.Code)

		if err != nil || !valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Code invalide ou expiré"})
			return
		}


		user, err := repos.UserRepository.GetUserByEmail(request.Email)

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur lors du hachage du mot de passe"})
			return
		}


		err = repos.UserRepository.UpdatePassword(user.ID, string(hashedPassword))

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur lors de la mise à jour"})
			return
		}


		_ = repos.ResetCodeRepository.DeleteResetCode(request.Email)


		c.JSON(http.StatusOK, gin.H{"message": "Mot de passe réinitialisé avec succès"})
	}
}
