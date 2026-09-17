package postgresql

import (
	"context"
	"uuid"

	"github.com/SirojWongpitakroj/hmf-audit/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type LogRepository struct {
	db *pgxpool.Pool
}

// create new db pool instance
func NewLogRepository(db *pgxpool.Pool) *LogRepository {
	return &LogRepository{
		db: db,
	}
}

func (r *LogRepository) Insert(ctx context.Context, log domain.Log) error {
	_, err := r.db.Exec(ctx,
		`
		INSERT INTO encrypted_logs (
			log_id,
			ciphertext,
			nonce,
			auth_tag,
			associated_data
		)
		VALUES ($1, $2, $3, $4, $5)
    	`,
		log.LogID,
		log.Ciphertext,
		log.Nonce,
		log.Tag,
		log.AD,
	)
	if err != nil {
		return err
	}
	return nil
}

func (r *LogRepository) GetByLogID(ctx context.Context, ids []uuid.UUID) (pgx.Rows, error) {
	rows, err := r.db.Query(ctx,
		`
		SELECT
			log_id,
			ciphertext,
			nonce,
			auth_tag,
			associated_data
		FROM encrypted_logs
		WHERE log_id = ANY($1)
		`,
		ids,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return rows, nil
}
