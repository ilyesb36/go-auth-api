package controllers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/ilyesb36/go-auth-api/controllers"
	"github.com/ilyesb36/go-auth-api/models"
	"github.com/ilyesb36/go-auth-api/repositories"
	"github.com/stretchr/testify/assert"
)

func TestRegister(t *testing.T) {
	mockUserRepo := &repositories.UserRepositoryMock{}
	repos := &repositories.Repositories{
		UserRepository: mockUserRepo,
	}

	user := models.User{
		Email:    "testuser1@example.com",
		Password: "password123",
	}

	userJSON, err := json.Marshal(user)
	assert.NoError(t, err)

	r := gin.Default()
	r.POST("/register", controllers.Register(repos))

	req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(userJSON))
	assert.NoError(t, err)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Inscription réussie", response["message"])

	t.Log("Réponse:", w.Body.String())
}
