// cmd/main.go is the runnable demo entry point for the usuario-auth library.
// It wires all layers together and starts the HTTP server.
//
// To use this library as a package in another project, import the individual
// packages (application, infrastructure/jwt, infrastructure/repository, etc.)
// and wire them in your own main.go.
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/rockefeller2021/usuario-auth/application"
	"github.com/rockefeller2021/usuario-auth/domain"
	nethttp "github.com/rockefeller2021/usuario-auth/infrastructure/http"
	"github.com/rockefeller2021/usuario-auth/infrastructure/jwt"
	"github.com/rockefeller2021/usuario-auth/infrastructure/repository"
	"github.com/rockefeller2021/usuario-auth/logger"
	"github.com/rockefeller2021/usuario-auth/server"
)

func main() {
	// ── Logger ───────────────────────────────────────────────────────────────
	// Use JSON format in production for log aggregators (Datadog, Loki, etc.)
	// Use text format in development for human-readable output.
	format := "text"
	if getEnv("ENV", "development") == "production" {
		format = "json"
	}
	appLog := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: format,
	})

	// ── JWT Manager ──────────────────────────────────────────────────────────
	// IMPORTANT: In production, use secrets of at least 32 random bytes loaded
	// from environment variables or a secrets manager (Vault, AWS SSM, etc.).
	jwtMgr := jwt.NewManager(jwt.Config{
		AccessSecret:    getEnv("JWT_ACCESS_SECRET", "change_me_access_super_secret_32ch"),
		RefreshSecret:   getEnv("JWT_REFRESH_SECRET", "change_me_refresh_super_secret_32c"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
	})

	// ── Repository ───────────────────────────────────────────────────────────
	// Set REPO=mysql in your environment to use MySQL persistence.
	// Defaults to the in-memory repository for quick local development.
	var repo domain.UserRepository
	if getEnv("REPO", "memory") == "mysql" {
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci",
			getEnv("MYSQL_USER", "root"),
			getEnv("MYSQL_PASSWORD", "Isaac2013*"),
			getEnv("MYSQL_HOST", "localhost"),
			getEnv("MYSQL_PORT", "3306"),
			getEnv("MYSQL_DATABASE", "usuario_auth"),
		)
		mysqlRepo, err := repository.NewMySQLUserRepository(dsn)
		if err != nil {
			log.Fatalf("❌ MySQL connection failed: %v", err)
		}
		defer mysqlRepo.Close()
		repo = mysqlRepo
		appLog.Info("✅ Repository: MySQL", "host", getEnv("MYSQL_HOST", "localhost"), "db", getEnv("MYSQL_DATABASE", "usuario_auth"))
	} else {
		repo = repository.NewMemoryUserRepository()
		appLog.Info("⚠️  Repository: in-memory (data will be lost on restart)")
	}

	// ── Application Layer ────────────────────────────────────────────────────
	svc     := application.NewAuthService(repo, jwtMgr, appLog)
	userSvc := application.NewUserService(repo, appLog)

	// ── HTTP Layer ───────────────────────────────────────────────────────────
	authHandler := nethttp.NewAuthHandler(svc, appLog)
	userHandler := nethttp.NewUserHandler(userSvc, appLog)
	router      := nethttp.NewRouter(authHandler, userHandler, jwtMgr, appLog, []string{"*"})

	// ── Server ───────────────────────────────────────────────────────────────
	srv := server.New(server.Config{
		Port:         getEnv("PORT", "8080"),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}, router, appLog)

	if err := srv.Run(); err != nil {
		log.Fatal(err)
	}
}

// getEnv returns the value of the environment variable identified by key,
// or fallback if the variable is not set.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
