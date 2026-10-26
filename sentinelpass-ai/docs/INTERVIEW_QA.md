# Interview Q&A
Short, technically accurate answers tied to this project.

**1. Why should passwords be hashed?**  
So a database leak does not reveal passwords. Servers only need to verify a password, never recover it, so one-way storage is enough.

**2. Hashing vs encryption?**  
Encryption is reversible with a key; hashing is one-way. Passwords should be hashed (with a slow, salted KDF), not encrypted, because anyone who steals the key can decrypt everything.

**3. Why use a salt?**  
A unique random salt per password makes identical passwords hash differently and defeats precomputed rainbow tables, forcing attackers to crack each hash separately. Salts are not secret.

**4. What is PBKDF2?**  
Password-Based Key Derivation Function 2: it applies an HMAC (here SHA-256) repeatedly (iterations) over password+salt. It is standardised (NIST/RFC 8018) and available in Python's `hashlib`.

**5. Why is password hashing intentionally slow?**  
Defenders hash once per login; attackers must hash billions of guesses. Raising cost multiplies attacker effort. Fast hashes like plain SHA-256 are the wrong tool.

**6. Why use constant-time comparison?**  
A normal `==` can return early at the first differing byte, leaking how much matched through timing. `hmac.compare_digest` takes the same time regardless.

**7. Why use `secrets` instead of `random`?**  
`random` is a predictable Mersenne Twister PRNG. `secrets` uses the OS CSPRNG, which is required for tokens, session IDs and salts.

**8. What is credential stuffing?**  
Replaying username/password pairs leaked from other sites. It works because people reuse passwords. Defences: unique passwords, MFA, rate limits, breach checks, risk-based login.

**9. What is brute force?**  
Trying many guesses against the login (online) or against stolen hashes (offline). Online: rate limit/lockout. Offline: slow hashes and strong passwords.

**10. What is account enumeration?**  
Learning which usernames exist from differences in messages, status codes or timing. Fix: identical responses, equalised work (dummy hash), neutral reset messages.

**11. How does account lockout work here?**  
After 5 consecutive failures `locked_until` is set 15 minutes ahead; logins during that time are refused with the generic error; success resets the counter.

**12. Why can lockout create DoS risks?**  
An attacker can deliberately fail logins for a victim's username and lock them out. Mitigations: per-user+IP rate keys, short auto-expiring locks, risk-based step-up instead of hard locks.

**13. Why hash reset tokens?**  
If the DB leaks, stored plaintext tokens would let attackers take over accounts. A SHA-256 of a 256-bit random token is safe to store; the user holds the real token.

**14. Why expire reset tokens?**  
A shorter lifetime shrinks the window in which a stolen/forwarded token is useful. This project uses 10 minutes and one-time use.

**15. What is password history?**  
Storing hashes of previous passwords to block reuse. It limits cycling back to old (possibly compromised) passwords.

**16. What is rate limiting?**  
Capping attempts per time window (here a sliding window per action/key) to slow brute force and abuse. Needs shared storage like Redis in multi-server deployments.

**17. What is session management?**  
Issuing, validating, expiring and revoking proof of an authenticated login. Here: random token, stored hashed, 30-min expiry, destroyed on password change.

**18. What is adaptive authentication?**  
Adjusting friction to risk: easy for normal logins, extra verification or restriction for suspicious ones.

**19. How does the risk engine work?**  
It sums weighted, named signals (failed attempts, new device/region, rapid location change, unusual hour...) into 0-100, maps to LOW/MEDIUM/HIGH/CRITICAL and returns an explanation listing the signals. Fully deterministic.

**20. Why should AI not make final security decisions?**  
LLMs are non-deterministic, can be manipulated by crafted input, can hallucinate, and are hard to audit. Deterministic rules are testable and explainable; AI adds explanation and prioritisation.

**21. Why should passwords never be sent to an LLM?**  
They would leave your trust boundary, may be logged or retained by a third party, and could leak. Only derived, non-reversible features are shared.

**22. How does the AI privacy layer work?**  
A whitelist sanitiser keeps only typed features; the provider sees nothing else; output passes a strict validator; failures fall back to a local advisor.

**23. What happens if the AI provider is unavailable?**  
The gateway catches the error and uses the local rule-based provider, tagging the result `local-fallback`. The app never depends on AI to function.

**24. How does anomaly detection work?**  
Statistics against the user's own history (e.g. login hour far from usual hours), findings for bursts and failure ratios, and an optional IsolationForest. Evidence already scored by a rule is not scored twice.

**25. How is synthetic security data generated?**  
The simulator creates `sim_*` accounts in the local DB, builds a baseline of normal logins using a controllable clock, then plays labelled scenarios (brute force, new device, unusual time, rapid location change, reset abuse, typos).

**26. What is threat modeling?**  
Systematically listing assets, attackers, threats, mitigations and residual risk. See the README table (Threat -> Mitigation -> Limitation).

**27. What is defense in depth?**  
Layering independent controls so one failure is not fatal: salted slow hashes + rate limits + lockout + risk scoring + audit logs + session expiry.

**28. What happens after a database compromise?**  
Attackers get salted PBKDF2 hashes and metadata, so they must crack each offline; weak passwords fall first. Reset tokens and session IDs are stored hashed. Response: rotate secrets, force resets, raise iterations/migrate algorithm.

**29. What are the limitations of PBKDF2?**  
It is CPU-bound only, so GPUs/ASICs attack it efficiently. Argon2id (memory-hard) is preferred; PBKDF2 remains acceptable for FIPS contexts with high iteration counts.

**30. How would you deploy this in production?**  
Put behind HTTPS with a real web framework, PostgreSQL + migrations, Redis rate limits, secrets manager, MFA/passkeys, email verification, centralised tamper-resistant logging/SIEM, monitoring and alerts, dependency scanning, backups and an incident-response plan.

**31. Why does the login error say the same thing for every failure?**  
Distinct messages (wrong password vs unknown user vs locked) let attackers map valid accounts. Detailed reasons go only to the audit log.

**32. Why destroy sessions when the password changes?**  
If an attacker already holds a session, changing the password should evict them; otherwise the credential change does nothing.
