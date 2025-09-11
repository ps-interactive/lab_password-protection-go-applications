package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sync"
)

// NOTE: This is the intentionally naive starting point to match the scenario.
// It uses a fast hash (sha256) without salt for passwords. We'll fix this in 01_bcrypt.

type user struct {
	Username string `json:"username"`
	// Insecure: storing a fast hash without salt
	PasswordHash string `json:"-"`
}

type store struct {
	mu    sync.RWMutex
	users map[string]user
}

func newStore() *store {
	return &store{users: make(map[string]user)}
}

func (s *store) addUser(u, pw string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[u]; exists {
		return httpError{status: http.StatusConflict, msg: "user exists"}
	}
	h := sha256.Sum256([]byte(pw))
	s.users[u] = user{Username: u, PasswordHash: hex.EncodeToString(h[:])}
	log.Printf("DEBUG: added user %q with hash %q", u, hex.EncodeToString(h[:]))
	return nil
}

func (s *store) verify(u, pw string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.users[u]
	if !ok {
		return false
	}
	h := sha256.Sum256([]byte(pw))
	return rec.PasswordHash == hex.EncodeToString(h[:])
}

type httpError struct {
	status int
	msg    string
}

func (e httpError) Error() string { return e.msg }

type creds struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	log.Println("Lockbox auth (00_start) listening on :8080")
	st := newStore()

	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var c creds
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if c.Username == "" || c.Password == "" {
			http.Error(w, "missing fields", http.StatusBadRequest)
			return
		}
		if err := st.addUser(c.Username, c.Password); err != nil {
			if he, ok := err.(httpError); ok {
				http.Error(w, he.msg, he.status)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "registered"})
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var c creds
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if st.verify(c.Username, c.Password) {
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
