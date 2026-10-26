# Architecture (beginner friendly)

## Layers

| Layer | Folder | Job |
|---|---|---|
| Interface | `cli/`, `dashboard.py` | talk to the human; **no** security logic |
| Services | `auth/` | registration, login, change/reset password, sessions |
| Security building blocks | `security/` | hashing, strength, policy, tokens, rate limiter, risk, anomaly |
| Data | `database/`, `models/` | SQL lives only in `repositories.py` |
| Observability | `audit/`, `reports/` | structured logs, statistics, reports |
| AI | `ai/` | providers, gateway (sanitise/validate/fallback), explainers |
| Simulation | `simulator/` | synthetic events + detector evaluation |
| Wiring | `app_context.py` | creates everything and injects dependencies |

**Dependency injection (what/why/how):** instead of each class creating its own database or hasher, `build_context()`
creates them once and passes them in. This lets tests swap the clock, mailbox and settings, and lets you swap PBKDF2 for Argon2id without editing auth code.

**Repository pattern:** one class per table group holds all SQL. Services call `users.get_by_username(...)`, never raw SQL, so SQL injection risk stays in one reviewed place (and all queries are parameterised).

## Login data flow

1. rate-limit check (per `username|ip_label`)
2. fetch user; if missing, hash a dummy password (so timing doesn't reveal existence)
3. if locked/inactive -> generic error
4. verify password (constant-time compare)
5. failure: counter+1, risk score, lock at 5, audit
6. success: build risk context from history (known devices/regions, recent attempts, lockouts, reset requests, anomaly stats)
7. risk -> action: LOW session / MEDIUM step-up / HIGH restrict / CRITICAL lock
8. write `login_events` + `security_events`

## Risk scoring

Score = sum of named signal weights, capped at 100. Levels: <25 LOW, <50 MEDIUM, <75 HIGH, else CRITICAL.
Each fact is counted **once** (e.g. burst of attempts is scored by the frequency rule, not again by the anomaly detector).

| Signal | Weight |
|---|---|
| failed attempts | 8 each (max 6) |
| new device / new region | 15 / 10 |
| region change <= 60 min | 25 |
| unusual hour | 10 |
| >= 5 attempts in 5 min | 15 |
| password > 1 year old | 5 |
| lockout in last 24 h | 10 each (max 2) |
| >= 3 reset requests in 24 h | 10 |
| optional ML outlier | up to 20 |

## AI flow

`features -> sanitize (whitelist) -> provider -> validate_output -> AIAssessment`, any error -> local advisor.
