package controllers_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/ilyesb36/go-auth-api/controllers"

	_ "github.com/mattn/go-sqlite3"
)

func setupRouter(db *sql.DB) *gin.Engine {
	r := gin.Default()
	r.POST("/register", controllers.Register(db))
	r.POST("/login", controllers.Login(db))
	return r
}

func setupDatabase(db *sql.DB) {
	createTableQuery := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		email TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	);
	`
	_, err := db.Exec(createTableQuery)
	if err != nil {
		log.Fatal("Error creating table: ", err)
	}
}

func TestRegister(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	setupDatabase(db)

	router := setupRouter(db)

	user := map[string]string{
		"name":     "Test User",
		"email":    "test@example.com",
		"password": "password123",
	}
	jsonValue, _ := json.Marshal(user)

	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	log.Printf("Response: %s", w.Body.String())

	assert.Equal(t, http.StatusCreated, w.Code)
}
