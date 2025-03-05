package controllers

import (
	"net/http"
	"time"

	"github.com/ilyesb36/go-auth-api/config"
	"github.com/ilyesb36/go-auth-api/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"github.com/ilyesb36/go-auth-api/utils"
)

var users = []models.User{}

func Register(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	for _, u := range users {
		if u.Email == user.Email {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email déjà utilisé"})
			return
		}
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur lors du hachage du mot de passe"})
		return
	}
	user.Password = string(hashedPassword)
	users = append(users, user)

	c.JSON(http.StatusOK, gin.H{"message": "Inscription réussie"})
}

func Login(c *gin.Context) {
	var loginData struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&loginData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	for _, u := range users {
		if u.Email == loginData.Email {
			user = u
			break
		}
	}

	if user.Email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Utilisateur non trouvé"})
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Mot de passe incorrect"})
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
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

func ForgotPassword(c *gin.Context) {
	var request struct {
		Email string `json:"email"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Format invalide"})
		return
	}

	var user models.User
	for _, u := range users {
		if u.Email == request.Email {
			user = u
			break
		}
	}

	if user.Email == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "Utilisateur non trouvé"})
		return
	}

	token, err := utils.GenerateResetToken(user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur lors de la génération du token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Token généré", "reset_token": token})
}

func ResetPassword(c *gin.Context) {
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
	
	var user *models.User
	for i := range users {
		if users[i].Email == claims.Issuer {
			user = &users[i]
			break
		}
	}

	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Utilisateur non trouvé"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur lors du hachage du mot de passe"})
		return
	}
	user.Password = string(hashedPassword)

	c.JSON(http.StatusOK, gin.H{"message": "Mot de passe réinitialisé avec succès"})
}
