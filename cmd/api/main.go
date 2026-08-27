package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

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
		AllowOriginFunc: func(r *http.Request, origin string) bool {
			if strings.HasPrefix(r.URL.Path, "/.well-known/") {
				return true
			}
			for _, allowed := range cfg.AllowedOrigins {
				if allowed == "*" || allowed == origin {
					return true
				}
			}
			return false
		},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Use(chiMiddleware.Logger)
	r.Use(chiMiddleware.Recoverer)

	memBridge := bridge.NewMemoryBridge()
	bridgeHandler := handlers.NewBridgeHandler(memBridge)
	authHandler := handlers.NewAuthHandler(database, cfg, memBridge)
	vaultHandler := handlers.NewVaultHandler(database)
	wksHandler := handlers.NewWKSHandler(database)

	r.Get("/.well-known/openpgpkey/hu/{hash}", wksHandler.GetPublicKey)
	r.Get("/.well-known/openpgpkey/{domain}/hu/{hash}", wksHandler.GetPublicKey)

	// Public routes
	r.Post("/api/auth/login", authHandler.Login)

	// Health
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if err := database.Pool.Ping(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"error","db":"disconnected"}`))
			return
		}

		w.Write([]byte(`{"status":"ok","db":"connected"}`))
	})

	r.Get("/api/bridge/secret/{id}", bridgeHandler.ConsumeSecret)
	r.Post("/api/auth/srp/challenge", authHandler.SRPChallenge)

	// Protected routes (JWT)
	r.Group(func(r chi.Router) {
		r.Use(middleware.AuthMiddleware(database, cfg.JWTSecret))
		r.Get("/api/auth/me", authHandler.Me)
		r.Post("/api/auth/change-password", authHandler.ChangePassword)
		r.Post("/api/auth/logout-others", authHandler.LogoutOthers)
		r.Get("/api/auth/logout", authHandler.LogoutAll)
		r.Get("/api/vault", vaultHandler.GetVault)
		r.Post("/api/vault", vaultHandler.SyncVault)
		r.Delete("/api/vault/cache", vaultHandler.ClearMessageCache)
		r.Delete("/api/vault/cache/messages", vaultHandler.DeleteCachedMessages)
		r.Post("/api/bridge/secret", bridgeHandler.PushSecret)
	})

	// Internal routes
	r.Group(func(r chi.Router) {
		r.Use(middleware.InternalMiddleware(cfg.InternalSecret))
		r.Post("/api/internal/auth/register", authHandler.Register) // User creation / verifier storage
		r.Post("/api/internal/auth/srp/verify", authHandler.SRPVerify)
		r.Post("/api/internal/bridge/secret", bridgeHandler.InternalPushSecret)
	})

	// 4. Start server
	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("[OK] aurion-api server running on http://localhost%s (%s)", addr, cfg.Env)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
