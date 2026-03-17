package database

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
)

func NewPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}

	return pool, nil
}

func RunMigrations(databaseURL string) error {
	m, err := migrate.New("file:///migrations", databaseURL)
	if err != nil {
		return fmt.Errorf("migration init error: %w", err)
	}
	defer func() {
		srcErr, dbErr := m.Close()
		if srcErr != nil {
			log.Printf("migration source close error: %v", srcErr)
		}
		if dbErr != nil {
			log.Printf("migration db close error: %v", dbErr)
		}
	}()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		// Handle dirty database by forcing the current version and retrying
		if strings.Contains(err.Error(), "Dirty database version") {
			version, _, vErr := m.Version()
			if vErr != nil {
				return fmt.Errorf("migration version error: %w", vErr)
			}
			log.Printf("dirty database at version %d, forcing and retrying", version)
			if forceErr := m.Force(int(version)); forceErr != nil {
				return fmt.Errorf("migration force error: %w", forceErr)
			}
			if retryErr := m.Up(); retryErr != nil && retryErr != migrate.ErrNoChange {
				return fmt.Errorf("migration error after force: %w", retryErr)
			}
		} else {
			return fmt.Errorf("migration error: %w", err)
		}
	}

	log.Println("database migrations applied successfully")
	return nil
}
