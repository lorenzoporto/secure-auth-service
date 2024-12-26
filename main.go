package main

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/crypto/argon2"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

type Config struct {
	Tokens struct {
		Refresh struct {
			Length              int           `json:"length"`
			Expiry              time.Duration `json:"expiry"`
			RotationGracePeriod int           `json:"rotationGracePeriod"`
			Version             string        `json:"version"`
			SigningKey          string        `json:"signingKey"`
		} `json:"refresh"`
		Access struct {
			Expiry    time.Duration `json:"expiry"`
			Algorithm string        `json:"algorithm"`
		} `json:"access"`
	} `json:"tokens"`
	Security struct {
		MaxSessions      int     `json:"maxSessions"`
		AnomalyThreshold float64 `json:"anomalyThreshold"`
		RateLimit        struct {
			Window int `json:"window"`
			Max    int `json:"max"`
		} `json:"rateLimit"`
		Argon2 struct {
			Time    uint32 `json:"time"`
			Memory  uint32 `json:"memory"`
			Threads uint8  `json:"threads"`
			KeyLen  uint32 `json:"keyLen"`
		} `json:"argon2"`
		MFA struct {
			Enabled    bool          `json:"enabled"`
			TOTPExpiry time.Duration `json:"totpExpiry"`
		} `json:"mfa"`
	} `json:"security"`
}

type SecurityContext struct {
	Token             string    `json:"token"`
	UserID            string    `json:"userId"`
	DeviceFingerprint string    `json:"deviceFingerprint"`
	IPAddress         string    `json:"ipAddress"`
	UserAgent         string    `json:"userAgent"`
	GeoLocation       *Location `json:"geoLocation"`
	Timestamp         time.Time `json:"timestamp"`
	TLSVersion        string    `json:"tlsVersion"`
	CipherSuite       string    `json:"cipherSuite"`
	Headers           Headers   `json:"headers"`
	MFACode           string    `json:"mfaCode,omitempty"`
}

type Location struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Accuracy  float64 `json:"accuracy"`
}

type Headers map[string]string

type TokenService struct {
	config      Config
	db          *sql.DB
	redis       *redis.Client
	logger      *zap.Logger
	metrics     *prometheus.Registry
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	rateLimiter *RateLimiter
	cache       *sync.Map
}

type RateLimiter struct {
	mu      sync.RWMutex
	buckets map[string]*TokenBucket
	config  Config
}

type TokenBucket struct {
	tokens   float64
	lastFill time.Time
	capacity float64
	fillRate float64
}

func NewTokenService(config Config, db *sql.DB, redis *redis.Client, logger *zap.Logger, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *TokenService {
	return &TokenService{
		config:      config,
		db:          db,
		redis:       redis,
		logger:      logger,
		metrics:     prometheus.NewRegistry(),
		privateKey:  privateKey,
		publicKey:   publicKey,
		rateLimiter: NewRateLimiter(config),
		cache:       &sync.Map{},
	}
}

func (s *TokenService) ValidateAndRotateToken(ctx context.Context, secCtx *SecurityContext) (*TokenResponse, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "ValidateAndRotateToken")
	defer span.Finish()

	if err := s.checkRateLimit(secCtx.IPAddress); err != nil {
		return nil, fmt.Errorf("rate limit exceeded: %w", err)
	}

	if err := s.validateSecurityContext(ctx, secCtx); err != nil {
		return nil, fmt.Errorf("invalid security context: %w", err)
	}

	token, err := s.verifyAndDecodeToken(ctx, secCtx.Token)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	if err := s.detectAnomalies(ctx, secCtx, token); err != nil {
		s.notifySecurityTeam(ctx, secCtx, err)
		return nil, fmt.Errorf("security anomaly detected: %w", err)
	}

	newTokens, err := s.rotateTokens(ctx, token, secCtx)
	if err != nil {
		return nil, fmt.Errorf("token rotation failed: %w", err)
	}

	if err := s.auditLog(ctx, "token_rotation", secCtx, newTokens); err != nil {
		s.logger.Error("audit logging failed", zap.Error(err))
	}

	return newTokens, nil
}

func (s *TokenService) generateAccessToken(ctx context.Context, userID string, claims map[string]interface{}) (string, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "generateAccessToken")
	defer span.Finish()

	now := time.Now()
	standardClaims := jwt.StandardClaims{
		Subject:   userID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(s.config.Tokens.Access.Expiry).Unix(),
		Issuer:    "auth-service",
	}

	tokenClaims := jwt.MapClaims{
		"standard": standardClaims,
		"custom":   claims,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)
	signedToken, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("token signing failed: %w", err)
	}

	return signedToken, nil
}

func (s *TokenService) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	span, ctx := opentracing.StartSpanFromContext(ctx, "handleLogin")
	defer span.Finish()

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if err := s.validateCredentials(ctx, req.Username, req.Password); err != nil {
		s.metrics.CounterVec("login_failures", []string{"reason"}).WithLabelValues("invalid_credentials").Inc()
		time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond) // Prevent timing attacks
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if s.config.Security.MFA.Enabled {
		if err := s.validateMFACode(ctx, req.UserID, req.MFACode); err != nil {
			http.Error(w, "Invalid MFA code", http.StatusUnauthorized)
			return
		}
	}

	tokens, err := s.createSessionTokens(ctx, req.UserID, extractSecurityContext(r))
	if err != nil {
		http.Error(w, "Session creation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}

func (s *TokenService) validateCredentials(ctx context.Context, username, password string) error {
	user, err := s.getUserByUsername(ctx, username)
	if err != nil {
		return err
	}

	hash := argon2.IDKey(
		[]byte(password),
		user.Salt,
		s.config.Security.Argon2.Time,
		s.config.Security.Argon2.Memory,
		s.config.Security.Argon2.Threads,
		s.config.Security.Argon2.KeyLen,
	)

	if subtle.ConstantTimeCompare(hash, user.PasswordHash) != 1 {
		return ErrInvalidCredentials
	}

	return nil
}

func (s *TokenService) detectAnomalies(ctx context.Context, secCtx *SecurityContext, token *Token) error {
	anomalyScore := 0.0

	// Check location anomaly
	if prevLocation, err := s.getLastKnownLocation(ctx, token.UserID); err == nil {
		distance := calculateDistance(prevLocation, secCtx.GeoLocation)
		if distance > s.config.Security.AnomalyThreshold {
			anomalyScore += 0.5
		}
	}

	// Check device fingerprint
	if prevFingerprint, err := s.getLastKnownDevice(ctx, token.UserID); err == nil {
		if prevFingerprint != secCtx.DeviceFingerprint {
			anomalyScore += 0.3
		}
	}

	// Check access patterns
	if unusual, err := s.detectUnusualAccessPattern(ctx, token.UserID, secCtx); err == nil && unusual {
		anomalyScore += 0.2
	}

	if anomalyScore >= 0.7 {
		return ErrAnomalyDetected
	}

	return nil
}
