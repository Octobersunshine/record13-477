package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"securitygroup/config"
	"securitygroup/firewall"
	"securitygroup/handlers"
	"securitygroup/repository"
	"securitygroup/service"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	setupLogLevel(cfg.LogLevel)

	log.Printf("Starting Security Group API Server...")
	log.Printf("  Port: %d", cfg.Port)
	log.Printf("  DB Path: %s", cfg.DBPath)
	log.Printf("  Firewall Mode: %s", cfg.FirewallMode)
	log.Printf("  Auto Sync: %v", cfg.AutoSync)

	repo, err := repository.NewSQLiteRepository(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to initialize repository: %v", err)
	}
	log.Println("Repository initialized (SQLite)")

	var backend firewall.FirewallBackend
	switch cfg.FirewallMode {
	case config.ModeNetsh:
		backend = firewall.NewWindowsNetshBackend()
	case config.ModeMock:
		backend = firewall.NewMockBackend()
	default:
		log.Fatalf("Unsupported firewall mode: %s", cfg.FirewallMode)
	}
	log.Printf("Firewall backend initialized: %s", backend.Name())

	fwManager := firewall.NewManager(backend)

	svc, err := service.NewRuleService(repo, fwManager, cfg.AutoSync)
	if err != nil {
		log.Printf("Warning: Initial firewall sync failed: %v", err)
		log.Println("Continuing without initial sync. Use POST /api/rules/sync to sync manually.")
		svc, err = service.NewRuleService(repo, fwManager, false)
		if err != nil {
			log.Fatalf("Failed to initialize service: %v", err)
		}
	}
	log.Println("Rule service initialized")

	handler := handlers.NewRuleHandler(svc)

	router := setupRouter(handler, cfg.TrustedProxy)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("HTTP server listening on :%d", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutdown signal received, gracefully shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited successfully")
}

func setupLogLevel(level string) {
	switch level {
	case "debug":
		gin.SetMode(gin.DebugMode)
	case "error":
		gin.SetMode(gin.ReleaseMode)
	default:
		gin.SetMode(gin.ReleaseMode)
	}
}

func setupRouter(handler *handlers.RuleHandler, trustedProxy string) *gin.Engine {
	r := gin.Default()

	if trustedProxy != "" {
		r.SetTrustedProxies([]string{trustedProxy})
	}

	r.Use(corsMiddleware())
	r.Use(gin.Recovery())

	api := r.Group("/api")
	{
		api.GET("/health", handler.GetHealth)

		rules := api.Group("/rules")
		{
			rules.POST("", handler.CreateRule)
			rules.GET("", handler.ListRules)
			rules.GET("/:id", handler.GetRule)
			rules.PUT("/:id", handler.UpdateRule)
			rules.DELETE("/:id", handler.DeleteRule)
			rules.POST("/sync", handler.SyncRules)
		}
	}

	return r
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
