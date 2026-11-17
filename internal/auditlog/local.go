package auditlog

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// RequireLoopbackHost rejects any host that is not this machine. The ingest
// and auditor commands are for the local Docker stack only; they must never
// be pointed at a remote database.
func RequireLoopbackHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("refusing non-local host %q: only localhost/127.0.0.1 is allowed", host)
}

// RequireLoopbackDSN applies RequireLoopbackHost to a PostgreSQL URL.
func RequireLoopbackDSN(dsn string) error {
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Hostname() == "" {
		return fmt.Errorf("PostgreSQL DSN must be a postgres:// URL with a host")
	}
	return RequireLoopbackHost(parsed.Hostname())
}
