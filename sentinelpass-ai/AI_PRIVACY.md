# AI Privacy & Safety Model

SentinelPass AI works with **no AI service at all** (`AI_PROVIDER=local`, the default). External AI is optional and
strictly limited.

## What the AI receives

Only a whitelisted, type-checked set of **derived features** (see `ai/gateway.py`):

* Password advisor: length, has-upper/lower/number/special, repeated/sequential/keyboard/date pattern flags,
  common-password flag, username-similarity (0-1), entropy estimate, strength score.
* Login-risk explainer: risk score, risk level, and a list of `(signal name, weight)` from a fixed set of names.
* Security analyst: aggregate counts (users, logins, suspicious logins, reset requests, risk distribution, weak-password %).

Anything not on the whitelist is dropped *before* the provider is called (`sanitize()`), including unknown keys.

## What the AI never receives

Passwords, password hashes, salts, reset tokens, session tokens, API keys, usernames, emails, IP/region/device labels,
or raw audit-log lines.

## Local fallback

If `AI_PROVIDER=local`, the key is missing, the provider name is unsupported, the network fails, the reply is not valid
JSON, or the validator rejects the reply, the **local rule-based advisor** produces the answer. Responses show a
`source` (`local`, `api:<name>`, `local-fallback`).

## API mode

`AI_PROVIDER=anthropic|openai` plus `AI_API_KEY` (environment only; never in code, never logged). Requests use HTTPS to the
provider's public endpoint with a 15 s timeout.

## Treating AI output as untrusted (prompt-injection considerations)

* Output must be a JSON object with `risk` (allowed label), `explanation` (<= 500 chars) and `recommendations` (<= 6 x 200 chars).
  Extra keys are dropped.
* URLs, code fences, shell/SQL fragments and "ignore previous instructions"-style text cause rejection (explanation)
  or removal (recommendations).
* Output is **displayed only**. It is never executed, evaluated, written to the database, or used to change settings,
  unlock accounts, or delete logs.
* For login explanations, the displayed risk level always comes from the deterministic engine; the AI cannot change it.
* Inputs contain no free text from attackers (usernames, user agents, etc.), which removes the main injection channel.

## Privacy limitations

* Exact password **length** and a strength score are sent in API mode; if that is unacceptable, use `AI_PROVIDER=local`.
* Aggregate counts can still reveal facts about your deployment to the provider.
* A provider's own retention/logging policies apply; review them before enabling API mode.
* The validator is a filter, not a guarantee; an LLM can still produce a wrong or misleading (but harmless-looking) explanation.
