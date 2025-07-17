package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"` // ou juste un booléen si pas encore de JWT
}

var db *sql.DB

func main() {

	connStr := fmt.Sprintf(
		"user=%s password=%s dbname=%s host=%s port=%s sslmode=disable",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Erreur connexion DB:", err)
	}
	defer db.Close()

	createTable()

	http.HandleFunc("/users", createUserHandler)
	http.HandleFunc("/login", corsMiddleware(LoginUsersHandler))

	log.Println("API en écoute sur :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func createTable() {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		email TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	);
	`
	_, err := db.Exec(query)
	if err != nil {
		log.Fatal("Erreur création table :", err)
	}
}

func createUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil || user.Email == "" || user.Password == "" {
		http.Error(w, "Corps invalide", http.StatusBadRequest)
		return
	}

	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Erreur de chiffrement", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO users (email, password) VALUES ($1, $2)", user.Email, string(hashedPwd))
	if err != nil {
		http.Error(w, "Erreur d'insertion", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, "Utilisateur créé avec succès")
}

// Fonction handler : vérifie si l'utilisateur existe et si le mot de passe correspond
func LoginUsersHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Recherche l'utilisateur par email
	var user User
	err := db.QueryRow("SELECT id, email, password FROM users WHERE email = $1", req.Email).Scan(&user.ID, &user.Email, &user.Password)
	if err == sql.ErrNoRows {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Vérifie le mot de passe avec bcrypt
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Si tu veux, tu peux générer un JWT ici
	// token := generateJWT(user) ...

	// Réponse (ici on ne retourne que "success" en brut)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LoginResponse{
		Token: "fake-jwt-token-or-real-one",
	})
}

// Middleware CORS
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Autorise les requêtes depuis ton frontend Angular
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:4200")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Gère les requêtes de prévalidation (preflight)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	}
}
