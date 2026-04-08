<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License">
  <img src="https://img.shields.io/badge/asyncio-powered-blueviolet?style=flat-square" alt="Asyncio">
  <img src="https://img.shields.io/badge/OSV.dev-integrated-orange?style=flat-square" alt="OSV.dev">
</p>

<h1 align="center">Vigil Security</h1>

<p align="center">
  <strong>Open-source personal security agent</strong><br>
  Monitors your infrastructure, scans dependencies, detects secrets, alerts via Telegram.
</p>

---

## What It Does

Vigil is a single tool that replaces a patchwork of security scripts. Point it at your projects and infrastructure — it finds vulnerabilities, leaked credentials, expiring certificates, open ports, and downed services. Get results in the terminal, as JSON/HTML reports, or as Telegram alerts.

```
$ vigil scan --path ./my-project

=== Vigil Security Scan Report ===

[dependency] 3 finding(s)
  [CRITICAL] GHSA-xxxx: express@4.17.1
    Known prototype pollution vulnerability.
    Fix: Update express to a patched version.

[secret] 2 finding(s)
  [CRITICAL] AWS Access Key ID detected
    Location: ./config/deploy.py:14
    Fix: Rotate the AWS access key immediately.

  [HIGH] Generic Password in Config
    Location: ./settings.py:8
    Fix: Move the credential to an environment variable.

[ssl_cert] 1 finding(s)
  [MEDIUM] SSL certificate expiring for api.example.com
    Certificate expires in 18 days on 2026-04-23.

--- Summary ---
Total findings: 6
Critical: 2
High: 1
```

## Features

| Scanner | What It Checks | Data Source |
|---------|---------------|-------------|
| **Dependency Scanner** | Known CVEs in your dependencies | [OSV.dev](https://osv.dev) (free, public API) |
| **Secret Detector** | Leaked API keys, tokens, passwords, private keys | 18+ regex patterns |
| **Port Scanner** | Open ports on your hosts, flags risky services | Direct TCP probing |
| **SSL Monitor** | Certificate expiration with configurable thresholds | Live TLS handshake |
| **Uptime Monitor** | HTTP health checks on your endpoints | HTTP requests |

### Supported Dependency Formats

`package.json` `requirements.txt` `Pipfile.lock` `poetry.lock` `Gemfile.lock` `go.sum` `Cargo.lock` `composer.lock`

### Detected Secret Types

AWS keys, GitHub tokens (PAT, OAuth, fine-grained), Telegram bot tokens, Slack tokens/webhooks, Google API keys, Stripe keys, SendGrid keys, Heroku keys, OpenAI keys, private keys (RSA/EC/DSA/OPENSSH), database connection strings, JWTs, generic passwords in config files.

## Installation

```bash
# From source
git clone https://github.com/alexff91/vigil-security.git
cd vigil-security
pip install -e ".[dev]"

# Verify installation
vigil --version
```

## Quick Start

```bash
# 1. Copy and edit the config
cp config.example.yaml vigil.yaml

# 2. Scan the current directory for secrets and vulnerable dependencies
vigil scan --path .

# 3. Scan with JSON output
vigil scan --format json -o report.json

# 4. Generate an HTML report
vigil report --format html -o security-report.html

# 5. Run a specific scanner only
vigil scan --scanner secret --path ./src

# 6. Continuous monitoring (every 5 minutes)
vigil monitor --interval 300 --telegram
```

## Configuration

Create a `vigil.yaml` in your project root (or pass `--config path/to/vigil.yaml`). Environment variables are supported with `${VAR_NAME}` syntax.

```yaml
# Telegram alerts
telegram:
  bot_token: "${VIGIL_TELEGRAM_TOKEN}"
  chat_id: "${VIGIL_TELEGRAM_CHAT_ID}"
  enabled: true

# Scan these project directories for vulnerable dependencies
dependencies:
  enabled: true
  paths:
    - "./frontend"
    - "./backend"

# Scan for leaked secrets
secrets:
  enabled: true
  paths:
    - "."
  exclude_patterns:
    - "node_modules"
    - ".venv"
    - "*.lock"
  max_file_size_kb: 512

# Check these hosts for open ports
ports:
  enabled: true
  hosts:
    - "myserver.example.com"
  ports: [22, 80, 443, 3306, 5432, 6379, 27017]
  timeout: 2.0

# Monitor SSL certificates
ssl:
  enabled: true
  hosts:
    - "example.com"
    - "api.example.com"
  warn_days: 30
  critical_days: 7

# HTTP health checks
uptime:
  enabled: true
  endpoints:
    - name: "Production"
      url: "https://example.com"
      expected_status: 200
    - name: "API"
      url: "https://api.example.com/health"
      timeout: 5
```

## Architecture

```
vigil-security/
├── vigil/
│   ├── __init__.py          # Package metadata
│   ├── cli.py               # CLI entry point (argparse)
│   ├── config.py            # YAML config loader with env var substitution
│   ├── engine.py            # Scan orchestrator (async)
│   ├── models.py            # Finding, ScanResult, Severity
│   ├── scanners/
│   │   ├── base.py          # Abstract scanner interface
│   │   ├── dependency.py    # OSV.dev vulnerability checker
│   │   ├── secret.py        # Regex-based secret detector
│   │   ├── port.py          # Async TCP port scanner
│   │   ├── ssl_cert.py      # TLS certificate monitor
│   │   └── uptime.py        # HTTP health checker
│   ├── alerts/
│   │   ├── telegram.py      # Telegram Bot API alerter
│   │   └── console.py       # Terminal output with colors
│   └── reporters/
│       ├── json_reporter.py # JSON report generator
│       └── html_reporter.py # Styled HTML report generator
├── tests/                   # pytest test suite
├── config.example.yaml      # Example configuration
├── pyproject.toml           # Project metadata and dependencies
└── README.md
```

### Design Decisions

- **asyncio throughout** — scanners run concurrently, port scans are parallel
- **Zero mandatory config** — works out of the box scanning the current directory
- **Plugin architecture** — each scanner is independent, easy to add new ones
- **Environment variables** — no credentials stored in config files
- **Redacted output** — secrets are never printed in full in findings

## Telegram Setup

1. Create a bot via [@BotFather](https://t.me/botfather)
2. Get your chat ID by messaging [@userinfobot](https://t.me/userinfobot)
3. Set environment variables:

```bash
export VIGIL_TELEGRAM_TOKEN="your-bot-token"
export VIGIL_TELEGRAM_CHAT_ID="your-chat-id"
```

4. Enable in config and run:

```bash
vigil scan --telegram
```

## CI/CD Integration

Add Vigil to your pipeline to catch vulnerabilities before they ship:

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    pip install vigil-security
    vigil scan --path . --format json -o vigil-report.json
    # Fails with exit code 1 if critical findings exist
```

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=vigil --cov-report=term-missing

# Lint
ruff check vigil/ tests/

# Type check
mypy vigil/
```

## Contributing

Contributions welcome. Some ideas:

- **New scanners**: Docker image scanning, Kubernetes config audit, GitHub Actions permissions
- **New alert backends**: Slack, Discord, PagerDuty, email
- **New report formats**: PDF, Markdown, SARIF
- **Pattern additions**: More secret detection patterns
- **Performance**: Caching OSV results, incremental scanning

## License

[MIT](LICENSE) -- Aleksandr Fedorov
