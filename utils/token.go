package utils

import (
	"time"
	"os"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
)

var secretKey = os.Getenv("JWT_SECRET")

func GenerateResetToken(email string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    email,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
	})

	return token.SignedString([]byte(secretKey))
}

func VerifyResetToken(tokenString string) (*jwt.RegisteredClaims, error) {
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


func ExtractExpFromJWT(tokenString string) (int64, error) {
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

func ExtractEmailFromJWT(tokenString string) (string, error) {
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

func ExtractEmailAndExpFromJWT(tokenString string) (string, int64, error) {
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