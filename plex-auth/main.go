package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

var db *sql.DB

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	var err error
	db, err = sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
	}

	if err := db.Ping(); err != nil {
		log.Fatalf("DB not responding: %v", err)
	}

	if err := createSchema(); err != nil {
		log.Fatalf("Failed to initialize DB schema: %v", err)
	}

	r := mux.NewRouter()
	r.HandleFunc("/auth/start", startAuthHandler).Methods("GET")
	r.HandleFunc("/auth/callback/{pin}", callbackHandler).Methods("GET")

	log.Println("Starting Plex Auth on :8080")
	http.ListenAndServe(":8080", r)
}