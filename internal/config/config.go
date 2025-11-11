package config

import (
    "fmt"
    "os"
    "strconv"
    "time"
)

// Config holds environment driven settings for the service.
type Config struct {
    AppEnv              string
    HTTPAddr            string
    DBDSN               string
    NATSURL             string
    AuthModeratorIss    string
    AuthModeratorAud    string
    CacheTTL            time.Duration
}

// Load reads configuration from environment variables applying defaults where necessary.
func Load() (Config, error) {
    cfg := Config{
        AppEnv:           getEnv("APP_ENV", "dev"),
        HTTPAddr:         getEnv("HTTP_ADDR", ":8080"),
        DBDSN:            os.Getenv("DB_DSN"),
        NATSURL:          getEnv("NATS_URL", "nats://nats:4222"),
        AuthModeratorIss: os.Getenv("AUTH_MODERATOR_JWT_ISS"),
        AuthModeratorAud: os.Getenv("AUTH_MODERATOR_JWT_AUD"),
    }
    ttl, err := parseDurationSeconds(getEnv("CACHE_TTL_SECONDS", "60"))
    if err != nil {
        return Config{}, fmt.Errorf("invalid CACHE_TTL_SECONDS: %w", err)
    }
    cfg.CacheTTL = ttl
    return cfg, nil
}

func getEnv(key, fallback string) string {
    if v := os.Getenv(key); v != "" {
        return v
    }
    return fallback
}

func parseDurationSeconds(v string) (time.Duration, error) {
    sec, err := strconv.Atoi(v)
    if err != nil {
        return 0, err
    }
    return time.Duration(sec) * time.Second, nil
}
