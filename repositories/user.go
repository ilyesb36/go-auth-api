package repositories

import (
	"database/sql"
	"fmt"
	"github.com/ilyesb36/go-auth-api/models"
)

type UserRepository interface {
	InsertUser(user *models.User) (int, error)
	GetUserByEmail(email string) (*models.User, error)
	EmailExists(email string) (bool, error)
	GetUserIDByEmail(email string) (int, error)
	UpdatePassword(userID int, newPassword string) error
}

type UserRepositoryImpl struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) UserRepository {
	return &UserRepositoryImpl{db: db}
}

func (repo *UserRepositoryImpl) InsertUser(user *models.User) (int, error) {
	var insertedID int
	query := `
		INSERT INTO users (name, email, password) 
		VALUES ($1, $2, $3) 
		RETURNING id;
	`
	err := repo.db.QueryRow(query, user.Name, user.Email, user.Password).Scan(&insertedID)
	if err != nil {
		return 0, err
	}
	return insertedID, nil
}

func (repo *UserRepositoryImpl) GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	query := `
		SELECT id, name, email, password 
		FROM users
		WHERE email = $1;
	`
	err := repo.db.QueryRow(query, email).Scan(&user.ID, &user.Name, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("utilisateur non trouvé pour l'email : %s", email)
		}
		return nil, err
	}
	return &user, nil
}


func (repo *UserRepositoryImpl) GetUserIDByEmail(email string) (int, error) {
	var userID int
	query := `
		SELECT id 
		FROM users 
		WHERE email = $1;
	`
	err := repo.db.QueryRow(query, email).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("utilisateur non trouvé pour l'email : %s", email)
		}
		return 0, err
	}
	return userID, nil
}

func (repo *UserRepositoryImpl) EmailExists(email string) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM users
			WHERE email = $1
		);
	`
	err := repo.db.QueryRow(query, email).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func (repo *UserRepositoryImpl) UpdatePassword(userID int, newPassword string) error {
	query := `
		UPDATE users
		SET password = $1
		WHERE id = $2;
	`
	_, err := repo.db.Exec(query, newPassword, userID)
	return err
}
