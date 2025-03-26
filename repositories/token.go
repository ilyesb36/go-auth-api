package repositories

import (
	"database/sql"

	"github.com/ilyesb36/go-auth-api/models"
)

type TokenRepository interface {
	InsertToken(token *models.Expired) (int, error)
	TokenIsInvalidate(token string) (bool, error)
}

type TokenRepositoryImpl struct {
	db *sql.DB
}

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
