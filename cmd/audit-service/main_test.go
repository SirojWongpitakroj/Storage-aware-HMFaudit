package main

import (
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	t.Setenv("AUDIT_HTTP_ADDR", "127.0.0.1:9090")
	t.Setenv("AUDIT_SYSTEM_ID", "experiment")
	t.Setenv("AUDIT_LOCATOR_TREE_ID", "ALL-test")
	t.Setenv("AUDIT_SHUTDOWN_TIMEOUT", "3s")
	t.Setenv("HPP_MAX_CONCURRENCY", "12")
	t.Setenv("CASSANDRA_HOSTS", "node-1, node-2")
	t.Setenv("CASSANDRA_PORT", "9142")
	t.Setenv("CASSANDRA_KEYSPACE", "audit_test")
	t.Setenv("CASSANDRA_DATACENTER", "dc-test")
	t.Setenv("CASSANDRA_USERNAME", "user")
	t.Setenv("CASSANDRA_PASSWORD", "password")

	configuration, err := loadConfig()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if configuration.HTTPAddress != "127.0.0.1:9090" ||
		configuration.SystemID != "experiment" ||
		configuration.LocatorTreeID != "ALL-test" ||
		configuration.HPPConcurrency != 12 ||
		configuration.ShutdownTimeout != 3*time.Second {
		t.Fatalf("unexpected audit configuration: %+v", configuration)
	}
	if len(configuration.Cassandra.Hosts) != 2 ||
		configuration.Cassandra.Hosts[0] != "node-1" ||
		configuration.Cassandra.Hosts[1] != "node-2" ||
		configuration.Cassandra.Port != 9142 ||
		configuration.Cassandra.Username != "user" {
		t.Fatalf("unexpected Cassandra configuration: %+v", configuration.Cassandra)
	}
}

func TestLoadConfigRejectsInvalidConcurrency(t *testing.T) {
	t.Setenv("HPP_MAX_CONCURRENCY", "0")
	if _, err := loadConfig(); err == nil {
		t.Fatal("loadConfig accepted zero HPP concurrency")
	}
}
