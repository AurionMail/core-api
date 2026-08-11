package main

import (
	"fmt"
	"log"
	"net/http"

	"aurion-api/internal/bridge"
	"aurion-api/internal/config"
	"aurion-api/internal/db"
	"aurion-api/internal/handlers"
	"aurion-api/internal/middleware"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

func main() {
	// 1. Config
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// 2. Database
	database, err := db.Connect(cfg.DBConn)
	if err != nil {
		log.Fatalf("DB error: %v", err)
	}
	defer database.Close()

	// 3. Chi Router
	r := chi.NewRouter()
	r.Use(cors.Handler(cors.Options{
		// Explicit list of allowed origins (Webmail and CryptPad)
		AllowedOrigins:   cfg.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Preflight request (OPTIONS) cache duration in seconds
	}))
	r.Use(chiMiddleware.Logger)
	r.Use(chiMiddleware.Recoverer)

	memBridge := bridge.NewMemoryBridge()
	bridgeHandler := handlers.NewBridgeHandler(memBridge)
	authHandler := handlers.NewAuthHandler(database, cfg)
	vaultHandler := handlers.NewVaultHandler(database)

	// Public routes
	r.Post("/api/auth/login", authHandler.Login)

	// Health route with DB ping
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if err := database.Pool.Ping(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"error","db":"disconnected"}`))
			return
		}

		w.Write([]byte(`{"status":"ok","db":"connected"}`))
	})

	// Public routes for the ephemeral RAM bridge
	r.Get("/api/bridge/secret/{id}", bridgeHandler.ConsumeSecret)

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(middleware.AuthMiddleware(database, cfg.JWTSecret))
		r.Get("/api/auth/me", authHandler.Me)
		r.Get("/api/auth/logout", authHandler.LogoutAll)
		r.Get("/api/vault", vaultHandler.GetVault)
		r.Post("/api/vault", vaultHandler.SyncVault)
		r.Post("/api/bridge/secret", bridgeHandler.PushSecret)
	})

	r.Group(func(r chi.Router) {
		r.Use(middleware.InternalMiddleware(cfg.InternalSecret))

		r.Post("/api/internal/bridge/secret", bridgeHandler.InternalPushSecret)
	})

	// 4. Start server
	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("🚀 aurion-api server started on http://localhost%s (%s)", addr, cfg.Env)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
