# Secure Auth Lab 🛡️

> Enterprise-grade authentication service with security research components. 

[![Security Score](https://img.shields.io/badge/Security-A+-green)](https://github.com/yourusername/secure-auth-lab)
[![Lab Category](https://img.shields.io/badge/Category-API_Security-purple)](https://github.com/yourusername/secure-auth-lab)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## About This Lab 🎯

Production-ready authentication service with embedded security test cases. Demonstrates secure implementations while providing controlled environments for security research.

## Security Features 🔐

- RSA-256 signed JWTs
- Argon2id password hashing
- Hardware-backed MFA
- Adaptive rate limiting
- Anomaly detection
- Session binding

## Research Components 🔬

```go
// Configurable security controls for research
type SecurityControls struct {
    TokenSigningMethod jwt.SigningMethod
    PasswordHashCost   int
    MFARequired       bool
    RateLimitBypass   bool  // Research only
}
```

## Architecture 🏗️

- Go 1.21+ (Core service)
- PostgreSQL (User store)
- Redis (Session management)
- Kubernetes (Orchestration) 
- Prometheus (Security metrics)

## Security Modes 🛠️

```bash
# Production mode (All security controls)
make run-secure

# Research mode (Configurable controls)
make run-research

# Local development
make run-dev
```

