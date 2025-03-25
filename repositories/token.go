package repositories

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ilyesb36/go-auth-api/models"
)

type TokenRepository interface {
	InsertToken(token *models.Expired) (int, error)
	TokenIsInvalidate(token string) (bool, error)
	GenerateResetToken(email string) (string, error)
	VerifyResetToken(tokenString string) (*jwt.RegisteredClaims, error)
	ExtractExpFromJWT(tokenString string) (int64, error)
	ExtractEmailFromJWT(tokenString string) (string, error)
	ExtractEmailAndExpFromJWT(tokenString string) (string, int64, error)
}

type TokenRepositoryImpl struct {
	db *sql.DB
}

var secretKey = os.Getenv("JWT_SECRET")

func NewTokenRepository(db *sql.DB) TokenRepository {
	return &TokenRepositoryImpl{db: db}
}

func (repo *TokenRepositoryImpl) InsertToken(token *models.Expired) (int, error) {
	var insertedID int
	query := `
		INSERT INTO expired (user_id, token, expires_at) 
		VALUES ($1, $2, $3) 
		RETURNING id;
	`
	err := repo.db.QueryRow(query, token.UserID, token.Token, token.ExpiresAt).Scan(&insertedID)
	if err != nil {
		return 0, err
	}
	return insertedID, nil
}

func (repo *TokenRepositoryImpl) TokenIsInvalidate(token string) (bool, error) {
	var count int
	query := `
		SELECT COUNT(*) 
		FROM expired 
		WHERE token = $1;
	`
	err := repo.db.QueryRow(query, token).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func (repo *TokenRepositoryImpl) GenerateResetToken(email string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    email,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
	})

	return token.SignedString([]byte(secretKey))
}

func (repo *TokenRepositoryImpl) VerifyResetToken(tokenString string) (*jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return nil, err
	}

	return claims, nil
}

func (repo *TokenRepositoryImpl) ExtractExpFromJWT(tokenString string) (int64, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("méthode de signature inattendue")
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		return 0, fmt.Errorf("erreur lors du parsing du JWT: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if exp, ok := claims["exp"].(float64); ok {
			return int64(exp), nil
		}
		return 0, fmt.Errorf("le champ 'exp' est introuvable ou invalide")
	}
	return 0, fmt.Errorf("le JWT est invalide ou mal formé")
}

func (repo *TokenRepositoryImpl) ExtractEmailFromJWT(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("méthode de signature inattendue")
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		return "", fmt.Errorf("erreur lors du parsing du JWT: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if email, ok := claims["iss"].(string); ok {
			return email, nil
		}
		return "", fmt.Errorf("le champ 'email' est introuvable ou invalide")
	}
	return "", fmt.Errorf("le JWT est invalide ou mal formé")
}

func (repo *TokenRepositoryImpl) ExtractEmailAndExpFromJWT(tokenString string) (string, int64, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("méthode de signature inattendue")
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		return "", 0, fmt.Errorf("erreur lors du parsing du JWT: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {

		var email string
		if emailClaim, ok := claims["iss"].(string); ok {
			email = emailClaim
		} else {
			return "", 0, fmt.Errorf("le champ 'email' est introuvable ou invalide")
		}

		var exp int64
		if expClaim, ok := claims["exp"].(float64); ok {
			exp = int64(expClaim)
		} else {
			return "", 0, fmt.Errorf("le champ 'exp' est introuvable ou invalide")
		}

		return email, exp, nil
	}

	return "", 0, fmt.Errorf("le JWT est invalide ou mal formé")
}