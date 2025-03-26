package repositories

import "github.com/ilyesb36/go-auth-api/models"

type UserRepositoryMock struct{}

func (mock *UserRepositoryMock) EmailExists(email string) (bool, error) {
	if email == "testuser@example.com" {
		return true, nil
	}
	return false, nil
}

func (mock *UserRepositoryMock) InsertUser(user *models.User) (int, error) {
	user.ID = 1
	return user.ID, nil
}

func (mock *UserRepositoryMock) GetUserByEmail(email string) (*models.User, error) {
	if email == "testuser@example.com" {
		return &models.User{
			ID:       1,
			Email:    email,
			Password: "$2a$10$hashedPassword",
		}, nil
	}
	return nil, nil
}

func (mock *UserRepositoryMock) GetUserIDByEmail(email string) (int, error) {
	if email == "testuser@example.com" {
		return 1, nil
	}
	return 0, nil
}

func (mock *UserRepositoryMock) UpdatePassword(userID int, hashedPassword string) error {
	if userID == 1 {
		return nil
	}
	return nil
}
