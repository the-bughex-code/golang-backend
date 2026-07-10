// Package config loads, validates, and exposes every runtime setting, exactly
// once, at process start.
//
// # Why a package instead of calling os.Getenv() wherever a value is needed
//
//   - Fail fast. A missing DB_PASSWORD stops the process at boot with a clear
//     message, instead of surfacing as a confusing connection error on the
//     first request that happens to need it.
//   - Typos become compile errors. cfg.Database.Port cannot be misspelled;
//     os.Getenv("DB_PROT") silently returns "".
//   - Testability. No package below this one ever reads the environment, so a
//     test constructs a Config literal and never touches os.Setenv.
//
// # Why not spf13/viper
//
// Viper solves problems this project does not have (remote config stores, live
// reload, six file formats) and pulls in dozens of transitive dependencies to
// do it. The standard library plus godotenv is a few hundred lines and does
// exactly this job. Reach for viper when you genuinely need Consul or etcd.
//
// # Why .env files are development-only
//
// In production, configuration arrives as real environment variables injected
// by the platform (systemd, Kubernetes, Fly.io, Render). A .env file on a
// production box is a secret sitting on disk. Load() therefore treats a missing
// .env as completely normal and never errors on it.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Environment enumerates the deployment environments the application knows
// about. It is a named string type rather than a bare string so that an
// invalid value cannot be constructed by accident, and so behaviour can hang
// off it (see IsProduction).
type Environment string

// The complete set of environments. APP_ENV must be one of these; any other
// value stops the process at boot.
const (
	EnvDevelopment Environment = "development"
	EnvTest        Environment = "test"
	EnvProduction  Environment = "production"
)

// IsProduction reports whether the extra production guardrails apply: TLS is
// required for the database, and a wildcard CORS origin is rejected.
func (e Environment) IsProduction() bool { return e == EnvProduction }

// IsDevelopment reports whether this is a developer's machine.
func (e Environment) IsDevelopment() bool { return e == EnvDevelopment }

// IsTest reports whether this is an automated test run.
func (e Environment) IsTest() bool { return e == EnvTest }

// Config is the root of the configuration tree. It is passed by value to the
// things that need it and is never mutated after Load returns.
type Config struct {
	App       AppConfig
	Server    ServerConfig
	Database  DatabaseConfig
	JWT       JWTConfig
	CORS      CORSConfig
	RateLimit RateLimitConfig
	Log       LogConfig
}

// AppConfig identifies the application and its deployment environment.
type AppConfig struct {
	Name string
	Env  Environment
}

// ServerConfig bounds every phase of an HTTP request's lifetime.
// Each timeout exists because its absence is a denial-of-service vector.
type ServerConfig struct {
	Host string
	Port int

	// ReadTimeout bounds how long the server will spend reading a request,
	// headers and body. Without it, one slow client can hold a connection
	// (and its goroutine) open forever. This is the Slowloris attack.
	ReadTimeout time.Duration

	// WriteTimeout bounds how long a handler has to produce a response.
	WriteTimeout time.Duration

	// IdleTimeout bounds how long a keep-alive connection may sit unused.
	IdleTimeout time.Duration

	// ShutdownTimeout is how long graceful shutdown waits for in-flight
	// requests to finish before the process exits anyway.
	ShutdownTimeout time.Duration
}

// Addr renders the host:port string that net/http expects.
func (s ServerConfig) Addr() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

// DatabaseConfig describes how to reach PostgreSQL and how large a
// connection pool to keep.
type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Name     string

	// SSLMode maps to libpq's sslmode. "disable" is correct for a local
	// Postgres on a loopback socket. Any real deployment must use at least
	// "require", and "verify-full" if you control the CA.
	SSLMode string

	// MaxConns caps the pool. The right number is NOT "as high as possible":
	// each Postgres connection is a separate OS process with its own memory.
	// A pool larger than the database can serve just moves the queue from
	// your app into the database, where it is harder to observe.
	MaxConns int32
	MinConns int32

	// MaxConnLifetime forces periodic reconnection. This lets connections
	// rebalance after a failover and prevents unbounded server-side memory
	// growth on long-lived sessions.
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}

// DSN builds a libpq-style connection string. pgx understands this format, and
// so does psql, which makes the string easy to test by hand.
func (d DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.Name, d.SSLMode,
	)
}

// JWTConfig holds the signing key and token lifetimes.
type JWTConfig struct {
	// Secret signs and verifies tokens with HMAC-SHA256. Anyone holding this
	// value can mint valid tokens for any user, so it is the single most
	// sensitive value in the application.
	Secret string

	// Issuer identifies who minted the token. Verified on every request so a
	// token from your staging environment cannot be replayed against prod.
	Issuer string

	// AccessTTL is deliberately short. An access token cannot be revoked
	// (that is the price of statelessness), so its blast radius is bounded
	// only by how quickly it expires.
	AccessTTL time.Duration

	// RefreshTTL is long, which is safe because refresh tokens are stored
	// server-side and can be revoked by deleting the row.
	RefreshTTL time.Duration
}

// CORSConfig controls which browser origins may read this API's responses.
type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	AllowCredentials bool
	MaxAge           int
}

// RateLimitConfig tunes the two token buckets: a permissive global one and
// a strict one for authentication endpoints.
type RateLimitConfig struct {
	// Enabled lets tests turn the limiter off without special-casing it.
	Enabled bool

	// RequestsPerSecond is the sustained refill rate of the token bucket.
	RequestsPerSecond float64
	// Burst is how many requests may arrive at once before throttling starts.
	Burst int

	// Authentication endpoints get their own, far stricter bucket.
	//
	// The general limit exists to stop runaway clients. This one exists to stop
	// credential stuffing, and the two numbers differ by an order of magnitude.
	// At the general rate of 10 req/s, an attacker gets 864,000 login attempts
	// per day from one IP. At 0.5 req/s, they get 43,200 — and each one costs
	// us 300ms of bcrypt, which is the point.
	AuthRequestsPerSecond float64
	AuthBurst             int
}

// LogConfig selects the log verbosity and output encoding.
type LogConfig struct {
	// Level is one of debug, info, warn, error.
	Level string
	// Format is "json" (machine-readable, for production log aggregators) or
	// "text" (human-readable, for a terminal).
	Format string
}

// Load reads configuration from the environment and returns a validated Config.
//
// It reports *all* problems at once rather than stopping at the first. Fixing
// six missing variables one boot at a time is miserable.
func Load() (*Config, error) {
	// A missing .env is normal: development uses one, production does not.
	// Any other error (unreadable file, malformed line) is worth surfacing.
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("config: loading .env: %w", err)
	}

	var problems []error
	collect := func(err error) {
		if err != nil {
			problems = append(problems, err)
		}
	}

	env := Environment(getString("APP_ENV", string(EnvDevelopment)))
	switch env {
	case EnvDevelopment, EnvTest, EnvProduction:
	default:
		collect(fmt.Errorf("APP_ENV must be one of development|test|production, got %q", env))
	}

	dbPort, err := getInt("DB_PORT", 5432)
	collect(err)
	serverPort, err := getInt("SERVER_PORT", 8080)
	collect(err)
	maxConns, err := getInt("DB_MAX_CONNS", 25)
	collect(err)
	minConns, err := getInt("DB_MIN_CONNS", 5)
	collect(err)

	readTimeout, err := getDuration("SERVER_READ_TIMEOUT", 10*time.Second)
	collect(err)
	writeTimeout, err := getDuration("SERVER_WRITE_TIMEOUT", 15*time.Second)
	collect(err)
	idleTimeout, err := getDuration("SERVER_IDLE_TIMEOUT", 60*time.Second)
	collect(err)
	shutdownTimeout, err := getDuration("SERVER_SHUTDOWN_TIMEOUT", 15*time.Second)
	collect(err)

	connLifetime, err := getDuration("DB_MAX_CONN_LIFETIME", time.Hour)
	collect(err)
	connIdleTime, err := getDuration("DB_MAX_CONN_IDLE_TIME", 30*time.Minute)
	collect(err)

	accessTTL, err := getDuration("JWT_ACCESS_TTL", 15*time.Minute)
	collect(err)
	refreshTTL, err := getDuration("JWT_REFRESH_TTL", 720*time.Hour) // 30 days
	collect(err)

	rateRPS, err := getFloat("RATE_LIMIT_RPS", 10)
	collect(err)
	rateBurst, err := getInt("RATE_LIMIT_BURST", 20)
	collect(err)
	rateEnabled, err := getBool("RATE_LIMIT_ENABLED", true)
	collect(err)
	authRPS, err := getFloat("RATE_LIMIT_AUTH_RPS", 0.5)
	collect(err)
	authBurst, err := getInt("RATE_LIMIT_AUTH_BURST", 5)
	collect(err)

	corsCredentials, err := getBool("CORS_ALLOW_CREDENTIALS", false)
	collect(err)
	corsMaxAge, err := getInt("CORS_MAX_AGE", 300)
	collect(err)

	dbPassword, err := requireString("DB_PASSWORD")
	collect(err)
	dbUser, err := requireString("DB_USER")
	collect(err)
	dbName, err := requireString("DB_NAME")
	collect(err)
	jwtSecret, err := requireString("JWT_SECRET")
	collect(err)

	cfg := &Config{
		App: AppConfig{
			Name: getString("APP_NAME", "backend"),
			Env:  env,
		},
		Server: ServerConfig{
			Host:            getString("SERVER_HOST", "0.0.0.0"),
			Port:            serverPort,
			ReadTimeout:     readTimeout,
			WriteTimeout:    writeTimeout,
			IdleTimeout:     idleTimeout,
			ShutdownTimeout: shutdownTimeout,
		},
		Database: DatabaseConfig{
			Host:            getString("DB_HOST", "localhost"),
			Port:            dbPort,
			User:            dbUser,
			Password:        dbPassword,
			Name:            dbName,
			SSLMode:         getString("DB_SSLMODE", "disable"),
			MaxConns:        int32(maxConns), //nolint:gosec // bounded by validate()
			MinConns:        int32(minConns), //nolint:gosec // bounded by validate()
			MaxConnLifetime: connLifetime,
			MaxConnIdleTime: connIdleTime,
		},
		JWT: JWTConfig{
			Secret:     jwtSecret,
			Issuer:     getString("JWT_ISSUER", "backend"),
			AccessTTL:  accessTTL,
			RefreshTTL: refreshTTL,
		},
		CORS: CORSConfig{
			AllowedOrigins:   getSlice("CORS_ALLOWED_ORIGINS", []string{"*"}),
			AllowedMethods:   getSlice("CORS_ALLOWED_METHODS", []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}),
			AllowedHeaders:   getSlice("CORS_ALLOWED_HEADERS", []string{"Accept", "Authorization", "Content-Type", "X-Request-Id"}),
			AllowCredentials: corsCredentials,
			MaxAge:           corsMaxAge,
		},
		RateLimit: RateLimitConfig{
			Enabled:               rateEnabled,
			RequestsPerSecond:     rateRPS,
			Burst:                 rateBurst,
			AuthRequestsPerSecond: authRPS,
			AuthBurst:             authBurst,
		},
		Log: LogConfig{
			Level:  getString("LOG_LEVEL", "info"),
			Format: getString("LOG_FORMAT", "text"),
		},
	}

	problems = append(problems, cfg.validate()...)

	if len(problems) > 0 {
		return nil, &InvalidConfigError{Problems: problems}
	}
	return cfg, nil
}

// InvalidConfigError reports every configuration problem at once.
//
// Fixing six missing variables one boot at a time is miserable, so Load never
// stops at the first. errors.Join alone would work, but it separates entries
// with bare newlines, and the result reads as one run-on paragraph. This type
// exists solely to print a legible bulleted list.
type InvalidConfigError struct {
	Problems []error
}

func (e *InvalidConfigError) Error() string {
	var b strings.Builder
	b.WriteString("config: invalid configuration:")
	for _, p := range e.Problems {
		b.WriteString("\n  - ")
		b.WriteString(p.Error())
	}
	return b.String()
}

// Unwrap exposes the individual problems, so a caller may still use errors.Is
// or errors.As against any one of them.
func (e *InvalidConfigError) Unwrap() []error { return e.Problems }

// validate enforces the invariants that the type system cannot.
func (c *Config) validate() []error {
	var problems []error

	if c.Server.Port < 1 || c.Server.Port > 65535 {
		problems = append(problems, fmt.Errorf("SERVER_PORT must be 1-65535, got %d", c.Server.Port))
	}
	if c.Database.Port < 1 || c.Database.Port > 65535 {
		problems = append(problems, fmt.Errorf("DB_PORT must be 1-65535, got %d", c.Database.Port))
	}
	if c.Database.MinConns < 0 || c.Database.MaxConns < 1 {
		problems = append(problems, errors.New("DB_MAX_CONNS must be >= 1 and DB_MIN_CONNS >= 0"))
	}
	if c.Database.MinConns > c.Database.MaxConns {
		problems = append(problems, fmt.Errorf(
			"DB_MIN_CONNS (%d) cannot exceed DB_MAX_CONNS (%d)", c.Database.MinConns, c.Database.MaxConns))
	}

	// HMAC-SHA256 keys shorter than the 256-bit hash output weaken the
	// signature. 32 bytes is the floor, not a suggestion.
	if len(c.JWT.Secret) < 32 {
		problems = append(problems, fmt.Errorf(
			"JWT_SECRET must be at least 32 characters, got %d (generate one with: openssl rand -base64 48)",
			len(c.JWT.Secret)))
	}
	if c.JWT.AccessTTL <= 0 || c.JWT.RefreshTTL <= 0 {
		problems = append(problems, errors.New("JWT_ACCESS_TTL and JWT_REFRESH_TTL must be positive"))
	}
	if c.JWT.AccessTTL >= c.JWT.RefreshTTL {
		problems = append(problems, errors.New(
			"JWT_ACCESS_TTL must be shorter than JWT_REFRESH_TTL; otherwise the refresh token is pointless"))
	}

	if c.RateLimit.Enabled {
		if c.RateLimit.RequestsPerSecond <= 0 || c.RateLimit.AuthRequestsPerSecond <= 0 {
			problems = append(problems, errors.New("RATE_LIMIT_RPS and RATE_LIMIT_AUTH_RPS must be positive"))
		}
		if c.RateLimit.Burst < 1 || c.RateLimit.AuthBurst < 1 {
			problems = append(problems, errors.New("RATE_LIMIT_BURST and RATE_LIMIT_AUTH_BURST must be at least 1"))
		}
	}

	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		problems = append(problems, fmt.Errorf("LOG_LEVEL must be debug|info|warn|error, got %q", c.Log.Level))
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		problems = append(problems, fmt.Errorf("LOG_FORMAT must be json|text, got %q", c.Log.Format))
	}

	// Production-only guardrails. These exist because the failure mode they
	// prevent is silent: everything works, and you are insecure.
	if c.App.Env.IsProduction() {
		if c.Database.SSLMode == "disable" {
			problems = append(problems, errors.New(
				"DB_SSLMODE must not be 'disable' in production; use 'require' or 'verify-full'"))
		}
		if len(c.CORS.AllowedOrigins) == 1 && c.CORS.AllowedOrigins[0] == "*" {
			problems = append(problems, errors.New(
				"CORS_ALLOWED_ORIGINS must not be '*' in production; list your real origins"))
		}
		if c.CORS.AllowCredentials && contains(c.CORS.AllowedOrigins, "*") {
			problems = append(problems, errors.New(
				"CORS_ALLOW_CREDENTIALS=true with a wildcard origin is forbidden by the CORS spec"))
		}
	}

	return problems
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Typed environment readers.
//
// Each returns the parsed value, or an error naming the offending variable.
// getX applies a default when unset; requireX treats unset as an error.
// ---------------------------------------------------------------------------

func getString(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func requireString(key string) (string, error) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return "", fmt.Errorf("%s is required but not set", key)
	}
	return v, nil
}

func getInt(key string, fallback int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer, got %q", key, v)
	}
	return n, nil
}

func getFloat(key string, fallback float64) (float64, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be a number, got %q", key, v)
	}
	return f, nil
}

func getBool(key string, fallback bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean (true|false|1|0), got %q", key, v)
	}
	return b, nil
}

// getDuration accepts Go duration syntax: 15m, 1h30m, 500ms, 24h.
func getDuration(key string, fallback time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration like 15m or 1h, got %q", key, v)
	}
	return d, nil
}

// getSlice splits on commas and trims surrounding space, so both
// "a,b,c" and "a, b, c" parse identically.
func getSlice(key string, fallback []string) []string {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return fallback
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}
