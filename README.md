# sheltr
[![CI](https://github.com/tarnsecurity/sheltr/actions/workflows/ci.yml/badge.svg)](https://github.com/tarnsecurity/sheltr/actions/workflows/ci.yml)
> A secret scanner for your codebase. Find hardcoded API keys, tokens, and credentials before they end up somewhere they shouldn't.

Built by [Tarn](https://tarnsecurity.github.io/tarn/) — open source security & infra tooling.

---

## Install

```bash
pip install sheltr
```

Or from source:

```bash
git clone https://github.com/tarnsecurity/sheltr
cd sheltr
pip install -e ".[dev]"
```

## Usage

```bash
# Scan current directory
sheltr scan .

# Scan a specific file
sheltr scan .env

# Scan with exclusions
sheltr scan . --exclude tests/fixtures --exclude vendor

# Only show high severity
sheltr scan . --severity high

# JSON output (great for CI pipelines)
sheltr scan . --format json > results.json
```

## Example output

```
  sheltr scanning ./myproject

  myproject/config.py
    ● HIGH   line 12  AWS Access Key ID
      match: AKIAIO******

  myproject/.env
    ◆ MEDIUM  line 3  Generic Password Assignment
      match: superS******

  ────────────────────────────────────────────────────────────
  2 findings in 47 files  1 high  1 medium  0 low
```

## What it detects

| Category | Examples |
|---|---|
| Cloud credentials | AWS keys, GCP service accounts |
| API keys | Stripe, Twilio, SendGrid, Mailgun, Slack |
| Auth tokens | GitHub tokens, NPM, PyPI, OpenAI, Anthropic |
| Private keys | RSA, EC, PGP, OpenSSH |
| Passwords | Hardcoded password/secret/token assignments |
| Connection strings | Database URLs with embedded credentials |
| JWT tokens | Hardcoded JWTs |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings |
| `1` | Findings detected (or error) |

This makes sheltr easy to use in CI pipelines — a non-zero exit fails the build.

## CI / GitHub Actions

```yaml
- name: Scan for secrets
  run: |
    pip install sheltr
    sheltr scan . --severity high --format json
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Roadmap

- [ ] `.sheltrignore` support
- [ ] Custom pattern config file
- [ ] SARIF output format (GitHub Code Scanning compatible)
- [ ] Pre-commit hook
- [ ] Entropy-based detection

## License

MIT — built by [Tarn](https://tarnsecurity.github.io/tarn/)
