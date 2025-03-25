package config

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"
	_ "github.com/lib/pq"

	
	"github.com/ilyesb36/go-auth-api/models"
)

func ConnectDB() *sql.DB {
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	dbname := os.Getenv("DB_NAME")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")

	psqlInfo := fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s", host, port, dbname, user, password)

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatal("Erreur lors de la connexion à la base de données : ", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal("Impossible de se connecter à la base de données : ", err)
	}

	log.Println("Connexion à la base de données réussie!")
	return db
}

func InsertToken(db *sql.DB, userID int, token string, expiresAt time.Time) (int, error) {
	var insertedID int
	query := `
		INSERT INTO expired (user_id, token, expires_at) 
		VALUES ($1, $2, $3) 
		RETURNING id;
	`
	err := db.QueryRow(query, userID, token, expiresAt).Scan(&insertedID)
	if err != nil {
		return 0, err
	}
	return insertedID, nil
}

func TokenIsInvalidate(db *sql.DB, token string) (bool, error) {
	var count int
	query := `
		SELECT COUNT(*) 
		FROM expired 
		WHERE token = $1;
	`

	err := db.QueryRow(query, token).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func InsertUser(db *sql.DB, user *models.User) (int, error) {
	var insertedID int
	query := `
		INSERT INTO users (name, email, password) 
		VALUES ($1, $2, $3) 
		RETURNING id;
	`
	err := db.QueryRow(query, user.Name, user.Email, user.Password).Scan(&insertedID)
	if err != nil {
		return 0, err
	}
	return insertedID, nil
}

func GetUserIDByEmail(db *sql.DB, email string) (int, error) {
	var userID int
	query := `
		SELECT id 
		FROM users 
		WHERE email = $1;
	`
	err := db.QueryRow(query, email).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("utilisateur non trouvé pour l'email : %s", email)
		}
		return 0, err
	}

	return userID, nil
}

func GetUserByEmail(db *sql.DB, email string) (*models.User, error) {
	var user models.User
	query := `
		SELECT id, name, email, password
		FROM users
		WHERE email = $1;
	`
	err := db.QueryRow(query, email).Scan(&user.ID, &user.Name, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("utilisateur non trouvé pour l'email : %s", email)
		}
		return nil, err
	}

	return &user, nil
}

func EmailExists(db *sql.DB, email string) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM users
			WHERE email = $1
		);
	`
	err := db.QueryRow(query, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("erreur lors de la vérification de l'email : %w", err)
	}
	return exists, nil
}

func UpdatePassword(db *sql.DB, userID int, newPassword string) error {
	query := `
		UPDATE users
		SET password = $1
		WHERE id = $2;
	`
	_, err := db.Exec(query, newPassword, userID)
	if err != nil {
		return fmt.Errorf("erreur lors de la mise à jour du mot de passe : %w", err)
	}
	return nil
}

func GetAllEmails(db *sql.DB) ([]string, error) {
	var emails []string
	query := `
		SELECT email 
		FROM users;
	`
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return nil, err
		}
		emails = append(emails, email)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return emails, nil
}

func GetEnv(key string, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
