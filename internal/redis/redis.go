package redisclient

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

func NewClient(redisURL string) (*redis.Client, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid Redis URL: %w", err)
	}

	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("unable to connect to Redis: %w", err)
	}

	return client, nil
}

// BlacklistJWT adds a JWT jti to the blacklist with the given TTL.
func BlacklistJWT(ctx context.Context, rdb *redis.Client, jti string, ttl time.Duration) error {
	return rdb.Set(ctx, "jwt_blacklist:"+jti, 1, ttl).Err()
}

// IsJWTBlacklisted returns true if the jti is in the blacklist.
func IsJWTBlacklisted(ctx context.Context, rdb *redis.Client, jti string) (bool, error) {
	val, err := rdb.Exists(ctx, "jwt_blacklist:"+jti).Result()
	if err != nil {
		return false, err
	}
	return val > 0, nil
}
