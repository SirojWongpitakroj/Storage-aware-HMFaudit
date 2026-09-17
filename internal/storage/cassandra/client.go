// Package cassandra implements the connection query between system and database
package cassandra

import (
	"context"
	"fmt"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
)

type Config struct {
	Hosts      []string
	Keyspace   string
	Datacenter string
	Username   string
	Password   string
	Port       int
}

func NewSession(ctx context.Context, cfg Config) (*gocql.Session, error) {
	cluster := gocql.NewCluster(cfg.Hosts...)
	cluster.Port = cfg.Port
	cluster.Keyspace = cfg.Keyspace

	session, err := cluster.CreateSession()
	if err != nil {
		return nil, err
	}
	return session, nil
}

func Ping(ctx context.Context, session *gocql.Session) error {
	var clusterName string
	var dataCenter string

	err := session.Query(
		`SELECT cluster_name, data_center FROM system.local;`,
	).Scan(&clusterName, &dataCenter)

	if err != nil {
		return fmt.Errorf("query cassandra ping: %w", err)
	}

	fmt.Println("Cluster: ", clusterName)
	fmt.Println("Data center: ", dataCenter)

	return nil
}
