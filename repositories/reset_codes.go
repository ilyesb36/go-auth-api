package repositories

import (
	"database/sql"
	"time"
)

type ResetCodeRepository interface {
	InsertResetCode(email string, code string, expiresAt time.Time) error
	VerifyResetCode(email string, code string) (bool, error)
	DeleteResetCode(email string) error
}

type ResetCodeRepositoryImpl struct {
	db *sql.DB
}

func NewResetCodeRepository(db *sql.DB) ResetCodeRepository {
	return &ResetCodeRepositoryImpl{db: db}
}

func (repo *ResetCodeRepositoryImpl) InsertResetCode(email string, code string, expiresAt time.Time) error {
	_, err := repo.db.Exec(
		`
			INSERT INTO reset_codes (email, code, expires_at)
			VALUES ($1, $2, $3)
		`, email, code, expiresAt)
	return err
}
func (repo *ResetCodeRepositoryImpl) VerifyResetCode(email string, code string) (bool, error) {
	var count int
	err := repo.db.QueryRow(
		`
			SELECT COUNT(*) FROM reset_codes
			WHERE email = $1 AND code = $2 AND expires_at > NOW()

		`, email, code).Scan(&count)
	return count > 0, err
}
func (repo *ResetCodeRepositoryImpl) DeleteResetCode(email string)error {
	_, err := repo.db.Exec(`DELETE FROM reset_codes WHERE email = $1`, email)
	return err
}
