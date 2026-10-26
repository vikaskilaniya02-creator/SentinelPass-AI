# SentinelPass AI

**AI-Assisted Password Security & Adaptive Authentication Platform**

![python](https://img.shields.io/badge/python-3.12%2B-blue) ![tests](https://img.shields.io/badge/tests-73%20passing-brightgreen) ![deps](https://img.shields.io/badge/core%20deps-stdlib%20only-lightgrey) ![scope](https://img.shields.io/badge/scope-defensive%20only-informational)

SentinelPass AI is a small but realistic **defensive** authentication platform: secure registration and login,
PBKDF2 password hashing, password-strength analysis, password history, secure reset, lockout, rate limiting,
sessions, audit logging, a transparent risk engine, anomaly detection, adaptive (risk-based) authentication, and an
AI layer that **explains** findings without ever making security decisions or seeing real passwords.

> **Responsible use:** this is a local learning/demo project. It contains no offensive tooling (no credential
> stealing, keylogging, malware, or attacks on external systems). All simulations run against the local database
> with synthetic accounts and fake region/device labels. Do not connect it to real accounts.

## Why this project?

It demonstrates concepts that come up in real security work and interviews:
password storage (salting, slow hashing, constant-time compare), authentication hardening (lockout, rate limiting,
enumeration resistance, reset tokens, session handling), logging without leaking secrets, risk-based/adaptive
authentication, **and** safe AI integration (privacy, untrusted-output handling, prompt-injection awareness,
deterministic fallback). It also measures its own detector on labelled synthetic data instead of just claiming it works.

*Salt ka simple matlab:* har password ke saath ek unique random value add karna, taaki same password ke hashes same na dikhein.
*AI ka role:* AI sirf explain/recommend karta hai. Final decision (lock, restrict, allow) hamesha deterministic code leta hai.

## Features

| Area | What is implemented |
|---|---|
| Passwords | PBKDF2-HMAC-SHA256 (configurable iterations, per-user salt, hash metadata stored), optional Argon2id behind an interface, NFKC normalisation |
| Strength | length, character classes, common/leet passwords, sequences, keyboard runs, repeats, dates, username/email similarity, entropy estimate (with stated limits) |
| Policy | NIST-style: length first, block common passwords, no forced rotation |
| Account safety | lockout (5 fails / 15 min), sliding-window rate limits (login, reset, register), password history, generic errors, dummy-hash timing equalisation |
| Reset | `secrets.token_urlsafe(32)`, only SHA-256 stored, 10-min expiry, atomic one-time use, neutral responses, per-account cap, DEMO-ONLY file mailbox |
| Sessions | random IDs, only hashes stored, 30-min expiry, refresh/destroy, destroyed on password change/reset |
| Audit | structured JSON-lines + DB, secrets redacted by key-name sanitiser |
| Risk | transparent weighted signals -> LOW / MEDIUM / HIGH / CRITICAL, explainable score |
| Adaptive auth | LOW allow, MEDIUM step-up code, HIGH temporary restriction, CRITICAL lock + event |
| Anomaly | per-user login-hour statistics, burst and failure-ratio findings, optional scikit-learn IsolationForest |
| AI | provider abstraction (local / Anthropic / OpenAI), feature whitelist, output validator, automatic local fallback |
| Tooling | CLI, Streamlit dashboard, synthetic simulator with precision/recall, JSON + HTML reports |

## Architecture

```
User
 |
CLI (cli/)  ---------------------->  Streamlit dashboard (read-only)
 |                                          ^
 v                                          |
Auth services: registration | authentication | password reset | session manager
 |            \                              |
 |             Rate limiter, Password policy + hasher
 v
Repositories (only place with SQL) --> SQLite
 |
 v
Audit logger --> security_events ---> Risk engine (rules) + Anomaly detector (stats)
                                              |
                                              v
                                   AI gateway: sanitise -> provider -> validate -> fallback
                                              |
                                              v
                                   Explanations / recommendations (display only)
```

Rule of thumb: UI -> services -> repositories. Hashing and AI sit behind interfaces. Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### Security architecture (login)

```
credentials -> rate limit -> lookup (dummy hash if unknown) -> lock check -> verify (constant-time)
  fail:    counter++, lock at 5, audit            success: risk engine (rules + stats)
                                                    LOW -> session | MEDIUM -> step-up | HIGH -> restrict | CRITICAL -> lock
```

### AI architecture

```
features only (no password) -> whitelist sanitiser -> provider (local | API) -> output validator -> display
                                                                     any failure -> local rule-based advisor
```
AI cannot execute code, write to the database, unlock accounts, or change settings. See [AI_PRIVACY.md](AI_PRIVACY.md).

## Database schema

`users`, `password_history`, `login_events`, `password_reset_tokens`, `sessions`, `security_events` (see `database/schema.py`).
Notable choices: history rows keep their own algorithm + iterations (old hashes stay verifiable); `login_events.user_id`
is nullable so attempts against unknown usernames are logged; `users.password_score` stores the strength score at
set-time (hashes are one-way, so this is the only way to report "weak password %").

## Installation

```bash
git clone <your-repo-url> sentinelpass-ai && cd sentinelpass-ai
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt                      # core app needs no packages; dashboard needs streamlit
cp .env.example .env                                     # optional
```

## Configuration

All settings are environment variables (or `.env`, never committed). See `.env.example`.

| Variable | Default | Meaning |
|---|---|---|
| `PASSWORD_HASH_ITERATIONS` | 600000 | PBKDF2 rounds (>=100000 enforced outside `APP_ENV=test`) |
| `PASSWORD_HISTORY_COUNT` | 5 | previous hashes checked |
| `MAX_FAILED_ATTEMPTS` | 5 | failures before lockout |
| `LOCKOUT_DURATION` | 15 | minutes |
| `RESET_TOKEN_EXPIRY` | 10 | minutes |
| `SESSION_EXPIRY` | 30 | minutes |
| `AI_PROVIDER` | local | `local`, `anthropic`, `openai` (needs `AI_API_KEY`, else local) |
| `ENABLE_ML_ANOMALY` | false | optional scikit-learn signal |

**Hash cost trade-off:** more iterations make offline cracking slower but also make every legitimate login slower and
give attackers a cheap way to burn your CPU. 600,000 is a common current PBKDF2-SHA256 starting point, not a universal
optimum. Benchmark on your hardware, aim for a noticeable but tolerable delay, and re-tune over time (hashes store their own iteration count).

## Usage

```bash
python app.py                              # CLI
streamlit run dashboard.py                 # dashboard (reads the same SQLite DB)
python -m simulator.security_simulator     # synthetic scenarios + detector evaluation (use --full for real hash cost)
pytest --cov=. --cov-report=term-missing   # tests
```

Quick demo: run the simulator, then open the dashboard and the CLI "Generate Security Report" option.
Simulated accounts are named `sim_*` and live in the same local database.

CLI preview (placeholder: add your own screenshot at `docs/img/cli.png`):

```
============================================
SENTINELPASS AI
Password & Authentication Security
============================================
  1. Register   2. Login   3. Check Password   4. Change Password   5. Forgot Password
  6. Security Dashboard   7. Security Events   8. AI Security Analysis
  9. Generate Security Report   10. Run Security Simulation   11. Exit
```
Dashboard screenshot placeholder: `docs/img/dashboard.png`.

## Detector evaluation (synthetic data)

`python -m simulator.security_simulator` labels every generated event as benign/malicious and reports the result.
A typical run on 42 events: precision ~0.87, recall ~0.90, false-positive rate ~0.31. Some scenarios are intentionally
hard (a user who mistypes their password four times looks like a brute-forcer; a night-time login on a known device is
only mildly suspicious). **These numbers describe a small synthetic benchmark, not real-world accuracy.**

## Threat model

| Threat | Mitigation | Limitation |
|---|---|---|
| Password database compromise | per-user salt, PBKDF2 600k, no plaintext, no reversible storage | weak passwords can still be cracked offline; no pepper/HSM |
| Offline cracking | slow hash, length-first policy, common-password blocking | no breached-password corpus check; PBKDF2 is not memory-hard (Argon2id optional) |
| Brute-force login | rate limit + lockout + risk score | distributed attacks defeat an in-process limiter |
| Credential stuffing | reuse history, risk signals (new device/region), step-up | no breach intelligence, no CAPTCHA/MFA |
| Account enumeration | generic errors, dummy hash timing, neutral reset replies | registration must reveal duplicates; side channels are not fully closed |
| Lockout DoS | per-user+IP rate keys, auto-expiring lock | an attacker can still temporarily lock a known username |
| Reset-token theft | high-entropy token, hashed at rest, 10-min expiry, one-time, per-account cap | demo delivers via a file; real email/link security out of scope |
| Session theft | random 256-bit IDs, hashed at rest, expiry, destroy on credential change | CLI has no cookies/TLS; no device binding |
| Password reuse | history of last N hashes | cannot detect reuse on other sites |
| Suspicious logins | explainable risk engine, anomaly stats, adaptive actions | heuristics: false positives and false negatives exist |
| Excessive reset requests | per-identifier limit + per-account cap | in-memory limiter resets on restart |
| Prompt injection / bad AI output | whitelist input, strict output validation, AI has no authority, local fallback | an LLM explanation can still be wrong or misleading |

This project reduces risk; it does **not** prevent these attacks completely.

## Testing

73 tests, ~86% coverage (`pytest --cov=.`): hashing, strength, registration, login, lockout, rate limiting, history, reset
(expiry, one-time use, caps), sessions, risk engine, anomaly, audit leak checks, AI validator/fallback, simulator, reports.
The CLI and Streamlit UI are thin and not unit-tested; the CLI was smoke-tested with scripted input.

## Security limitations

See [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md). In short: not production-ready, no MFA/TLS, in-memory rate-limit
and step-up state, SQLite single-node, demo mailbox, heuristic detectors.

## Future improvements

WebAuthn/passkeys, TOTP MFA, email verification, Redis rate limiting, PostgreSQL, Docker, CI security scanning
(pip-audit, bandit), SIEM/OpenTelemetry export, Argon2id by default, device fingerprinting, stronger ML anomaly detection,
SSO, RBAC, breached-password check (k-anonymity), FastAPI web UI.

## References (inspiration, not copied)

OWASP Authentication Cheat Sheet, OWASP Password Storage Cheat Sheet, OWASP Logging Cheat Sheet, OWASP ASVS,
NIST SP 800-63B, OWASP Top 10 for LLM Applications.

## Project layout

```
app.py  dashboard.py  app_context.py  exceptions.py  utils.py
config/ models/ database/ security/ auth/ ai/ audit/ reports/ cli/ simulator/ tests/ docs/
```

## License

MIT (replace the copyright holder in `LICENSE`).
