package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/SirojWongpitakroj/hmf-audit/internal/checkpoint"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
	"github.com/SirojWongpitakroj/hmf-audit/internal/localization"
	"github.com/SirojWongpitakroj/hmf-audit/internal/services"
	cassandrastore "github.com/SirojWongpitakroj/hmf-audit/internal/storage/cassandra"
	"github.com/SirojWongpitakroj/hmf-audit/internal/transport/httpapi"
	gocql "github.com/apache/cassandra-gocql-driver/v2"
)

type config struct {
	HTTPAddress     string
	SystemID        string
	LocatorTreeID   string
	HPPConcurrency  int
	ShutdownTimeout time.Duration
	Cassandra       cassandrastore.Config
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("audit service stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	configuration, err := loadConfig()
	if err != nil {
		return err
	}
	rootContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	startupContext, cancelStartup := context.WithTimeout(rootContext, 20*time.Second)
	defer cancelStartup()
	session, err := cassandrastore.NewSession(startupContext, configuration.Cassandra)
	if err != nil {
		return fmt.Errorf("connect to Cassandra: %w", err)
	}
	defer session.Close()

	checkpointStore, err := cassandrastore.NewCheckpointStore(session, configuration.LocatorTreeID)
	if err != nil {
		return err
	}
	checkpointReader, err := checkpoint.NewReader(configuration.SystemID, checkpointStore)
	if err != nil {
		return err
	}
	hppReader, err := cassandrastore.NewHPPReader(session, configuration.HPPConcurrency)
	if err != nil {
		return err
	}
	hppService, err := hpp.NewService(hppReader, hppReader)
	if err != nil {
		return err
	}
	localizationService, err := localization.NewService(hppService)
	if err != nil {
		return err
	}
	auditService, err := services.NewAuditService(
		checkpointReader,
		cassandrastore.NewALLRepo(session),
		hppService,
		localizationService,
	)
	if err != nil {
		return err
	}
	handler, err := httpapi.NewHandler(auditService, cassandraReadiness(session))
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              configuration.HTTPAddress,
		Handler:           requestLogger(logger, handler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("audit service listening",
			"address", configuration.HTTPAddress,
			"system_id", configuration.SystemID,
			"locator_tree_id", configuration.LocatorTreeID,
			"hpp_concurrency", configuration.HPPConcurrency,
		)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve audit API: %w", err)
	case <-rootContext.Done():
	}

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), configuration.ShutdownTimeout)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("shutdown audit API: %w", err)
	}
	logger.Info("audit service stopped gracefully")
	return nil
}

func loadConfig() (config, error) {
	port, err := integerEnvironment("CASSANDRA_PORT", 9042)
	if err != nil {
		return config{}, err
	}
	concurrency, err := integerEnvironment("HPP_MAX_CONCURRENCY", 8)
	if err != nil {
		return config{}, err
	}
	if concurrency <= 0 {
		return config{}, fmt.Errorf("HPP_MAX_CONCURRENCY must be positive")
	}
	shutdownTimeout, err := durationEnvironment("AUDIT_SHUTDOWN_TIMEOUT", 10*time.Second)
	if err != nil {
		return config{}, err
	}
	hosts := splitNonempty(environment("CASSANDRA_HOSTS", "127.0.0.1"))
	if len(hosts) == 0 {
		return config{}, fmt.Errorf("CASSANDRA_HOSTS must contain at least one host")
	}
	result := config{
		HTTPAddress:     environment("AUDIT_HTTP_ADDR", ":8080"),
		SystemID:        environment("AUDIT_SYSTEM_ID", "default"),
		LocatorTreeID:   environment("AUDIT_LOCATOR_TREE_ID", "ALL"),
		HPPConcurrency:  concurrency,
		ShutdownTimeout: shutdownTimeout,
		Cassandra: cassandrastore.Config{
			Hosts: hosts, Port: port,
			Keyspace:   environment("CASSANDRA_KEYSPACE", "hmf_audit"),
			Datacenter: environment("CASSANDRA_DATACENTER", "datacenter1"),
			Username:   os.Getenv("CASSANDRA_USERNAME"),
			Password:   os.Getenv("CASSANDRA_PASSWORD"),
		},
	}
	if result.HTTPAddress == "" || result.SystemID == "" || result.LocatorTreeID == "" {
		return config{}, fmt.Errorf("audit HTTP address, system ID, and locator tree ID are required")
	}
	return result, nil
}

func cassandraReadiness(session *gocql.Session) httpapi.ReadinessCheck {
	return func(ctx context.Context) error {
		var clusterName string
		return session.Query("SELECT cluster_name FROM system.local").ScanContext(ctx, &clusterName)
	}
}

func requestLogger(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		next.ServeHTTP(writer, request)
		logger.Info("HTTP request",
			"method", request.Method,
			"path", request.URL.Path,
			"duration_ms", time.Since(started).Milliseconds(),
		)
	})
}

func environment(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func integerEnvironment(name string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	return parsed, nil
}

func durationEnvironment(name string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}
	return parsed, nil
}

func splitNonempty(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
