package tests

import (
	"context"
	"os"
	"testing"

	"uuid" // matches whatever import path domain/log.go actually resolves against

	"github.com/SirojWongpitakroj/hmf-audit/internal/domain"
	"github.com/SirojWongpitakroj/hmf-audit/internal/storage/postgresql"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestInsert(t *testing.T) {
	if os.Getenv("HMF_AUDIT_INTEGRATION") != "1" {
		t.Skip("set HMF_AUDIT_INTEGRATION=1 after starting PostgreSQL to run integration tests")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, "postgres://hmf:hmfdev@localhost:5432/cloud_provider")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	repo := postgresql.NewLogRepository(pool)
	logID := uuid.New()
	l := domain.Log{
		LogID:      logID,
		Ciphertext: []byte("ct"),
		Nonce:      []byte("nonce"),
		Tag:        []byte("tag"),
		AD:         []byte("ad"),
	}

	if err := repo.Insert(ctx, l); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	var count int
	err = pool.QueryRow(ctx, "SELECT count(*) FROM encrypted_logs WHERE log_id = $1", logID).Scan(&count)
	if err != nil || count != 1 {
		t.Fatalf("row not found after insert: err=%v count=%d", err, count)
	}

	rows, err := repo.GetByLogID(ctx, []uuid.UUID{logID})
	if err != nil {
		t.Fatalf("GetByLogID failed: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatalf("GetByLogID returned no readable row: %v", rows.Err())
	}
	var gotID uuid.UUID
	var ciphertext, nonce, tag, ad []byte
	if err := rows.Scan(&gotID, &ciphertext, &nonce, &tag, &ad); err != nil {
		t.Fatalf("scan returned row: %v", err)
	}
	if gotID != logID || string(ciphertext) != "ct" || string(nonce) != "nonce" ||
		string(tag) != "tag" || string(ad) != "ad" {
		t.Fatalf("GetByLogID returned unexpected log data")
	}
	if rows.Next() {
		t.Fatal("GetByLogID returned more than one row")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate returned rows: %v", err)
	}
}
