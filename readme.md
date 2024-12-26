# Vulnerable Auth Lab 🔬

> A deliberately vulnerable authentication service for security research and learning. Part of Lorenzo Porto Labs.

[![Lab Difficulty](https://img.shields.io/badge/Difficulty-Medium-yellow)](https://github.com/yourusername/vulnerable-auth-lab)
[![Lab Category](https://img.shields.io/badge/Category-API_Security-purple)](https://github.com/yourusername/vulnerable-auth-lab)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## About This Lab 🎯

A deliberately vulnerable authentication service designed for API security research and training. Contains both secure implementations and common vulnerabilities for learning purposes.

## Security Research Areas 🔍

- JWT token vulnerabilities
- OAuth 2.0 implementation flaws
- MFA bypass techniques
- Rate limiting evasion
- Session management weaknesses
- Privilege escalation paths

## Lab Environment 🛠️

- Go 1.21+ (Backend API)
- PostgreSQL (User data, sessions)
- Redis (Rate limiting, caching)
- Kubernetes (Deployment)
- Prometheus (Metrics)

## Vulnerabilities 💉

This lab contains various vulnerabilities, including:

```go
// Example vulnerable code snippet
func validateToken(token string) bool {
    // VULN: Weak token validation
    return len(token) > 0
}
```

Full vulnerability list in [VULNERABILITIES.md](docs/VULNERABILITIES.md)

## Getting Started 🚀

```bash
# Run vulnerable version
make run-vuln

# Run secure version
make run-secure

# Deploy local lab
make deploy-lab
```

## Lab Modules 📚

1. Authentication Bypass
2. Token Security
3. MFA Weaknesses
4. Session Attacks
5. Rate Limiting Bypass

## Research Notes 📝

My findings, exploits, and security research:
[RESEARCH.md](docs/RESEARCH.md)

## Disclaimer ⚠️

This is a deliberately vulnerable application. Do not use in production.

## License

MIT License - See [LICENSE](LICENSE)

[@YourHandle](https://twitter.com/yourhandle) | [Blog](https://yourblog.com)