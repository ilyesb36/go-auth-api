package repositories

import (
	"database/sql"
)
type Repositories struct {
	UserRepository UserRepository
	TokenRepository TokenRepository
	ResetCodeRepository ResetCodeRepository
}

func NewRepositories(db *sql.DB) *Repositories {
	return &Repositories{
		UserRepository: NewUserRepository(db),
		TokenRepository: NewTokenRepository(db),
		ResetCodeRepository: NewResetCodeRepository(db),
	}
}