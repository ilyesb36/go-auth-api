package config

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	_ "github.com/lib/pq"
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

func ApplyMigrations() {
	host := strings.TrimSpace(os.Getenv("DB_HOST"))
	port := strings.TrimSpace(os.Getenv("DB_PORT"))
	dbname := strings.TrimSpace(os.Getenv("DB_NAME"))
	user := strings.TrimSpace(os.Getenv("DB_USER"))
	password := strings.TrimSpace(os.Getenv("DB_PASSWORD"))
	migrateVersion := strings.TrimSpace(os.Getenv("CD_MIGRATION"))
	fmt.Println("Application des migrations...")
	connect_string := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", user, password, host, port, dbname)
	var cmd *exec.Cmd

	if migrateVersion == "" {
		cmd = exec.Command("migrate", "-database", connect_string, "-path", "db/migrations", "up")
	} else {
		migrateVersion = fmt.Sprintf("%06s", migrateVersion)
		fmt.Println("migrateVersion:", migrateVersion)
		cmd = exec.Command("migrate", "-database", connect_string, "-path", "db/migrations", "goto", migrateVersion)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatal("Erreur lors de l'application des migrations :", err)
	}

	fmt.Println("Migrations appliquées avec succès.")
}
