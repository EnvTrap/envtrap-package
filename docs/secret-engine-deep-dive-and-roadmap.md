# EnvTrap Secret Detection Engine Deep Dive: Architecture, Node.js Internals, and Threat Model

A developer-focused, plain-English explanation of how EnvTrap automatically discovers, evaluates, and watches credentials without requiring manual secret configuration, explaining V8 internals, Shannon entropy, where current code has flaws, and what we are building next.

---

## 1. What is the Secret Engine and Why is it the Foundation?

Every security tool is only as good as what it knows to look for:
- If a security tool doesn't know that `sk_live_994829482` is a secret, it cannot block it when an attacker tries to leak it over HTTP, DNS, or a child process.
- But forcing developers to manually configure every secret in a file is brittle, error-prone, and destroys developer adoption.

The **Secret Detection Engine** is the brain of EnvTrap:
1. It automatically inspects your environment and files at boot.
2. It filters out thousands of harmless configuration variables (like `PORT=3000` or `NODE_ENV=production`).
3. It identifies real credentials using deterministic vendor signatures and Shannon entropy math.
4. It watches credentials as they rotate at runtime using V8 Proxy traps.

---

## 2. Node.js Internals: Where Secrets Live

To intercept secrets, we must understand how Node.js manages environment state:

### Node.js Internal 1: `process.env` and the V8 Environment Object
In Node.js, `process.env` is not a plain JavaScript object:
- In Node's C++ source (`src/env.cc` and `src/node_env_var.cc`), `process.env` is backed by a native C++ accessor template.
- When you set `process.env.FOO = 'bar'`, Node invokes the C library `setenv("FOO", "bar", 1)`.
- When you read `process.env.FOO`, Node reads from the OS environment block.
- All values in `process.env` are coerced to strings.

### Node.js Internal 2: Dotenv Parsing
Most Node.js applications use `.env` files. When packages like `dotenv` execute, they read the file from disk, parse lines on `=` boundaries, and assign them directly to `process.env`.

### Node.js Internal 3: V8 Proxy Traps
In ECMAScript, a `Proxy` object wraps a target object and intercepts fundamental operations:
- `set(target, prop, value)`: Intercepts property assignments.
- `deleteProperty(target, prop)`: Intercepts variable deletions.
EnvTrap installs a Proxy over `process.env` to detect secrets that are loaded or rotated *after* the application has booted.

### Node.js Internal 4: `MessageChannel` and `MessagePort`
When Node.js loads ESM loader hooks (`--import`), the loader runs in a **separate worker thread**, completely isolated from the application's main thread.
EnvTrap uses Node's `MessageChannel` to bridge the two:
- When `process.env` changes in the main thread, a message is posted across `port1`.
- The ESM loader worker receives the message on `port2` and updates its active secret registry in real time.

---

## 3. How EnvTrap Discovers and Validates Secrets

EnvTrap uses a three-stage lifecycle:

```
+-------------------------------------------------------------------------------+
| Stage 1: Candidate Ingestion (src/secrets/)                                   |
|                                                                               |
|  Source A: Active Shell (EnvSecretSource.ts)                                  |
|   - Reads process.env                                                         |
|   - Drops ~60 system variables via SYSTEM_BLOCKLIST (PATH, HOME, USER, etc.)  |
|                                                                               |
|  Source B: File Secrets (DotEnvSecretSource.ts)                               |
|   - Reads .env (or custom file)                                               |
|   - In v3.1: Explicit secrets retained even if matching generic names         |
|   - Filters out non-secret config keys (PORT, NODE_ENV, DEBUG, LOG_LEVEL)    |
+-------------------------------------------------------------------------------+
                                       │
                                       ▼
+-------------------------------------------------------------------------------+
| Stage 2: The Evaluation Gate (src/detection/fingerprint.ts)                   |
|                                                                               |
|  Test 1: Minimum Length Check                                                 |
|   - Length < 12 characters? Discarded (prevents short false positives).       |
|                                                                               |
|  Test 2: Deterministic Pattern Match (patterns.ts)                            |
|   - Matches Stripe, AWS, GitHub PAT, Slack, SendGrid, or Bearer token?        |
|   - YES -> Instantly registered as secret. Bypasses entropy check.            |
|                                                                               |
|  Test 3: Shannon Entropy Analysis                                             |
|   - Computes statistical randomness H = -∑ p * log2(p).                       |
|   - Score >= 3.5 bits/character? -> Registered as active secret.              |
+-------------------------------------------------------------------------------+
                                       │
                                       ▼
+-------------------------------------------------------------------------------+
| Stage 3: Live Runtime Synchronization (src/hooks/hooks.mjs)                   |
|                                                                               |
|  - process.env Proxy traps set/deleteProperty at runtime.                     |
|  - Transmits updates across MessageChannel port to ESM loader.                |
|  - Dynamic secrets from AWS Secrets Manager / Vault tracked without restart.  |
+-------------------------------------------------------------------------------+
```

---

## 4. Current Flaws & Bottlenecks in EnvTrap's Secret Engine

### Flaw 1: Encoded Secret Blind Spot (Issue #5)
Attackers rarely send raw strings. They encode secrets into Base64, URL-encoding, or Hex:
```javascript
const encoded = Buffer.from(process.env.DB_PASSWORD).toString('base64');
```
Currently, `SecretMatcher.ts` looks for exact substring matches of `secret.value`. It misses encoded variants.

### Flaw 2: Linear $O(N 	imes M)$ Substring Scanning (Issue #11)
Currently, `SecretMatcher.findIn()` loops through every registered secret and calls `content.includes(secret.value)`.
If you have 100 secrets and an application processes 10,000 requests per second, performing 100 string scans on every buffer introduces noticeable CPU overhead.

### Flaw 3: Hardcoded Minimum Length of 4 on File Secrets (Issue #55)
In `SecretMatcher.ts` and `DotEnvSecretSource.ts`, a minimum length of 4 characters is hardcoded for file secrets. Organizations cannot currently adjust this policy via `envtrap.json`.

---

## 5. Technical Roadmap: How We Are Upgrading the Secret Engine

```
                        Loaded Secrets Dictionary
                                    │
                                    ▼
             +---------------------------------------------+
             | Step 1: Pre-Generated Encoding Variants     |
             | For every secret, pre-compute:              |
             | - Base64 representation                     |
             | - Hex representation                        |
             | - URL-encoded representation                |
             +---------------------------------------------+
                                    │
                                    ▼
             +---------------------------------------------+
             | Step 2: Aho-Corasick Multi-Pattern Tree     |
             | Build an Aho-Corasick automaton once.       |
             | Scans any buffer in single pass O(N) time   |
             | regardless of how many secrets are loaded.  |
             +---------------------------------------------+
                                    │
                                    ▼
             +---------------------------------------------+
             | Step 3: Custom Regex Pattern Schema         |
             | Allow enterprises to supply custom token    |
             | regexes in envtrap.json (Issue #63).        |
             +---------------------------------------------+
                                    │
                                    ▼
                        Active Secret Watchlist
```

---

## 6. Configuration Reference in `envtrap.json`

```json
{
  "entropy": {
    "threshold": 3.5,
    "minLength": 12
  },
  "exclusions": {
    "envVars": ["KUBERNETES_SERVICE_HOST", "GIT_COMMIT_SHA"]
  }
}
```

---

## 7. Summary Table

| Problem | How It Works Now | What Was Wrong | How We Are Fixing It |
|:---|:---|:---|:---|
| **Manual Configuration** | Zero-config automatic discovery | Manual lists are never maintained | Dual shell + `.env` automatic candidate ingestion |
| **False Positives** | Filters short strings & known keys | Harmless variables trigger alarms | Entropy gate ($H \ge 3.5$) + length gate ($\ge 12$) |
| **Runtime Secret Rotation** | `process.env` Proxy + MessagePort | App secrets loaded dynamically missed | Real-time live synchronization (v3.0+) |
| **Encoded Credentials** | Plain substring search | Base64 / Hex bypasses detection | Pre-generated encoding variant dictionary (Issue #5) |
| **Scan Performance** | $O(N 	imes M)$ linear loop | High CPU on many secrets | Aho-Corasick single-pass search automaton (Issue #11) |\n