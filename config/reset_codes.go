package config

import (
	"database/sql"
	"time"
)

func InsertResetCode(db *sql.DB, email, code string, expiresAt time.Time) error {
	_, err := db.Exec(`
		INSERT INTO reset_codes (email, code, expires_at)
		VALUES ($1, $2, $3)
	`, email, code, expiresAt)
	return err
}

func VerifyResetCode(db *sql.DB, email, code string) (bool, error) {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM reset_codes
		WHERE email = $1 AND code = $2 AND expires_at > NOW()
	`, email, code).Scan(&count)

	return count > 0, err
}

func DeleteResetCode(db *sql.DB, email string) error {
	_, err := db.Exec(`DELETE FROM reset_codes WHERE email = $1`, email)
	return err
}
