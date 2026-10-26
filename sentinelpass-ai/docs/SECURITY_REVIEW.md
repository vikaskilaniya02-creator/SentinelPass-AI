# Security Review (honest assessment)

**Status: educational/demo project. Not production-ready**, even though tests pass locally.

## Strengths
* Passwords: per-user random salt, PBKDF2-HMAC-SHA256, per-record algorithm/iterations, constant-time comparison, NFKC normalisation.
* No plaintext secrets stored or logged; tokens and session IDs stored only as SHA-256 hashes (tests assert this).
* Enumeration resistance: identical login error text, dummy-hash timing, neutral reset replies, per-account reset cap.
* One-time, expiring reset tokens with atomic consumption; sessions destroyed on password change/reset.
* All SQL parameterised and isolated in one module.
* AI is advisory only, fed whitelisted features, and its output is validated; local fallback always exists.
* Detector is evaluated on labelled synthetic data rather than assumed to work.

## Known limitations / potential vulnerabilities
* **Lockout DoS:** anyone who knows a username can temporarily lock it (mitigated by rate-limit keys and auto-expiry, not eliminated).
* **Registration reveals existing usernames/emails** (inherent to the flow); a real product would use email verification.
* **In-memory state:** rate limiter and step-up codes live in one process; they reset on restart and do not scale across workers.
* **Step-up verification is a demo:** the code is returned in-process; real systems deliver it out-of-band, and should use TOTP/WebAuthn.
* **No TLS/cookies/CSRF** (CLI + local dashboard only); the Streamlit dashboard has no authentication and must stay local.
* **Time-based side channels** are reduced, not eliminated (e.g. locked-account path, DB lookup timing).
* **PBKDF2 is not memory-hard**; Argon2id (optional) is preferable where available.
* **No breached-password check**; strength score is a heuristic and can be wrong either way.
* Weak-password statistics rely on a score stored at set-time; the hash cannot be re-analysed.
* SQLite is single-node; there are no migrations, backups, encryption-at-rest or log tamper-protection.
* Simulated `sim_*` users share the application database.

## False positives / false negatives
* **False positives:** legitimate users who mistype passwords, travel, or use new devices get step-up or restriction (measured FP rate ~0.3 on the synthetic set).
* **False negatives:** a single low-and-slow attacker using a known device/region, or an attacker with the correct password and matching context, scores LOW.

## AI risks
* An LLM explanation may be wrong or over-confident; it never changes decisions.
* Validator rules are pattern-based and can be bypassed by creative text; impact is limited because output is display-only.
* API mode shares exact password length and aggregate counts with a third party.

## Privacy risks
Audit logs contain usernames/ids and region labels. Keep them access-controlled and define retention. Demo data is synthetic.

## Deployment risks
Secrets in `.env`, debug logging, shared hosts, missing monitoring, unmanaged dependency updates, running the dashboard publicly.

## Recommended next steps
MFA/passkeys, Redis-backed limits, PostgreSQL + migrations, breached-password k-anonymity check, Argon2id default,
CI with `pip-audit`/`bandit`, structured log shipping (SIEM), authenticated admin UI behind TLS, threat-model review by a second person.
