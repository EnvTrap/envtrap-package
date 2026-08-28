# envtrap

> [!IMPORTANT]
> **Repository Discontinued**: This repository has been discontinued and migrated to the **EnvTrap** organization at **[https://github.com/EnvTrap](https://github.com/EnvTrap)**, where the package now lives in its own dedicated repository.

A zero-configuration runtime secret leak detector and egress firewall for Node.js.

envtrap wraps your Node.js application and intercepts every outbound channel in real time — before secrets, credentials, or sensitive environment variables can be exfiltrated by malicious code, compromised packages, or insider threats.

Unlike static analysis (SAST) tools that scan source code at build time, envtrap operates **at execution time** — inspecting actual traffic, subprocesses, DNS queries, and output streams as they happen.

---

## Features

- **HTTPS/HTTP MITM Proxy** (`network` channel, default: `block`): Starts a local TLS proxy on `127.0.0.1`, routes all child process HTTP/HTTPS traffic through it, decrypts payloads, and scans headers, URLs, and request bodies for secrets. Loopback addresses and user-configured domains are automatically bypassed via `NO_PROXY`.
- **stdout / stderr Stream Scanning** (`stdout`/`stderr` channels, default: `warn`): Pipes the child process's standard streams, scans every chunk, redacts matched secrets (`[REDACTED: SHA256:<8-char>]`), and optionally kills the child on block.
- **Child Process Env Validation** (`child_process` channel, default: `warn`): Intercepts `spawn`, `exec`, `execFile`, `fork`, and sync variants to check `options.env` for secrets before any OS fork.
- **DNS Interception** (`dns` channel, default: `block`): Intercepts all `node:dns` APIs (callback and promise style) to block queries containing secret values in the hostname.
- **High-Entropy DNS Tunneling Detection**: Analyses each subdomain label for Shannon entropy ≥ threshold — flags potential base64/hex encoded DNS-tunneled payloads regardless of secret match.
- **Real-Time Secret Synchronization**: Wraps `process.env` in a `Proxy` — when secrets are set or deleted at runtime, the updated map is immediately broadcast to the ESM loader thread via a `MessageChannel`. No restart required.
- **ESM + CommonJS Coverage**: All module interception works for both ESM (`import`) via `module.register()` customization hooks, and CommonJS (`require()`) via `Module.prototype.require` patching.
- **AI-Safe Redaction**: Secret values are never logged. Only their SHA-256 hash prefix is shown in terminal output and the report file.
- **Structured Leak Reports**: After each run, `.envtrap-report.json` is written to CWD with all events in machine-readable JSON.
- **Granular Channel Control**: Each channel can be independently set to `block`, `warn`, or `off` via `envtrap.json`.

---

## Requirements

- **Node.js 18.0.0 or later** (ESM customization hooks require Node 18+)

---

## Installation

Install globally:

```bash
npm install -g envtrap
```

Install as a development dependency:

```bash
npm install --save-dev envtrap
```

Use without installing:

```bash
npx envtrap run node app.js
```

---

## Usage

Prefix your start command with `envtrap run`:

```bash
envtrap run node app.js
```

### Works with any Node.js framework

```bash
# Express / Fastify
envtrap run node server.js

# NestJS
envtrap run node dist/main.js

# Next.js (server-side)
envtrap run npm run start

# Bare scripts
envtrap run node scripts/migrate.js
```

### CLI Flags

```bash
# Custom .env file
envtrap run --env-file .env.production node app.js

# Disable HTTPS MITM proxy (no network channel scanning)
envtrap run --no-mitm node app.js

# Verbose debug output (proxy intercept logs, cert issuance)
envtrap run --verbose node app.js

# Quiet mode (suppress alerts, show summary only)
envtrap run --quiet node app.js

# Write structured JSONL events to a file
envtrap run --log-file logs/envtrap.jsonl node app.js
```

### package.json integration

```json
{
  "scripts": {
    "start": "envtrap run node app.js",
    "dev":   "envtrap run node --watch app.js"
  }
}
```

---

## Configuration (`envtrap.json`)

Create `envtrap.json` in your project root for fine-grained control. All fields are optional — envtrap ships with safe defaults.

```json
{
  "channels": {
    "stdout":        "warn",
    "stderr":        "warn",
    "network":       "block",
    "child_process": "warn",
    "dns":           "block"
  },
  "exclusions": {
    "domains": ["api.stripe.com", "api.openai.com"],
    "paths":   ["test/**", "**/__tests__/**"]
  },
  "entropy": {
    "threshold": 3.5,
    "minLength": 12
  },
  "quiet":   false,
  "logFile": null
}
```

### `channels`

Each key accepts `"block"`, `"warn"`, or `"off"`:

| Channel         | Default | Description                                          |
|-----------------|---------|------------------------------------------------------|
| `stdout`        | `warn`  | Scans every write to process.stdout, redacts secrets |
| `stderr`        | `warn`  | Scans every write to process.stderr, redacts secrets |
| `network`       | `block` | MITM proxy intercepts all HTTP/HTTPS traffic         |
| `child_process` | `warn`  | Checks `options.env` on all spawn/exec/fork calls    |
| `dns`           | `block` | Intercepts all `node:dns` resolution calls           |

### `exclusions`

- **`domains`**: Fully-qualified domain names that bypass network scanning entirely. These are also automatically added to the child process `NO_PROXY`/`no_proxy` env variable so local-only services are never routed through the MITM engine.
- **`paths`**: Glob patterns for source files — detections from matching files are suppressed (applies to `stdout`, `stderr`, `child_process`, `dns`)

### `entropy`

- **`threshold`** (default: `3.5`): Minimum Shannon entropy score for a value to be registered as an active secret
- **`minLength`** (default: `12`): Minimum character length — shorter values are always dropped

### `quiet`

When `true`, suppresses banner and per-leak alerts. Summary and report file are always produced.

### `logFile`

Path (relative or absolute) to append structured JSONL events during the run.

---

## Validate Configuration

```bash
envtrap check
```

Output on success: `✅ Configuration is valid.`
Output on failure shows the exact field path and error message.

---

## Secret Detection

On startup, envtrap loads secret candidates from two sources:

1. **`process.env`** — every env var not on the built-in system variable blocklist (`PATH`, `HOME`, `SHELL`, `NODE_ENV`, etc.)
2. **`.env` file** — parsed with `dotenv`, deduplicated against `process.env`

Each candidate value is tested through the `looksLikeSecret` gate:

1. **Length check**: must be ≥ `entropy.minLength` (default 12 chars)
2. **Deterministic regex**: if the value matches any known pattern (Stripe, AWS, GitHub, etc.), it is always registered
3. **Shannon entropy**: if entropy ≥ `entropy.threshold` (default 3.5), it is registered

### Built-in Token Patterns

| Provider                     | Pattern                                                    |
|------------------------------|------------------------------------------------------------|
| Stripe                       | `sk_live_...` or `sk_test_...` followed by 24+ chars      |
| AWS Access Key ID            | `AKIA[0-9A-Z]{16}`                                        |
| GitHub Personal Access Token | `ghp_[a-zA-Z0-9]{36}`                                     |
| Generic Bearer Token         | `Bearer` + 20+ alphanumeric/symbol chars                  |
| SendGrid API Key             | `SG.` + 22 chars + `.` + 43 chars                         |
| Slack Bot Token              | `xoxb-` + numeric segments + 24 alphanumeric chars        |

### Runtime Secret Rotation

If your application rotates or injects new credentials during execution (e.g. fetching a short-lived token from a vault), envtrap detects this automatically via a `process.env` Proxy wrapper:

```js
// This is detected and synced to the ESM loader thread in real time
process.env.VAULT_TOKEN = await vault.getToken();
```

No restart or reconfiguration needed.

---

## Scanning Details

- **Exact string match** only at runtime — fast even on large payloads
- **Sliding-window TCP scanner**: scans the current chunk combined with a 200-character overlap from the previous chunk, preventing O(n²) buffer allocations
- **1 MB backpressure clamp**: only the first 1 MB of any content chunk is scanned
- **TTL deduplication**: repeated `secret + channel` events within a 1.5-second window are silently dropped to prevent alert flooding

---

## AI-Safe Redaction

envtrap never logs secret values. It uses SHA-256 fingerprinting:

- **In terminal output**: `Bearer [REDACTED: SHA256:f23831a9]`
- **In `.envtrap-report.json`**: full SHA-256 hex digest stored, raw value never written

```json
[
  {
    "secretName": "STRIPE_SECRET_KEY",
    "source": "env",
    "channel": "network",
    "context": "Outbound HTTPS Request Audited:\n  Destination Host: attacker.com\n  ...",
    "sha256": "baf2ae563873...",
    "timestamp": 1781335024545
  }
]
```

---

## Architecture

```
  ┌──────────────────────────────────────────────────────────────────────┐
  │  envtrap CLI  (parent process)                                        │
  │                                                                        │
  │  ┌───────────────────────────┐  ┌───────────────────────────────┐     │
  │  │  MITM TLS Proxy           │  │  Stream Scanner               │     │
  │  │  127.0.0.1:<random port>  │  │  (stdout + stderr pipes)      │     │
  │  │  Scans HTTP/HTTPS traffic │  │  Scans + redacts output       │     │
  │  │  Native RSA via OpenSSL   │  │  Sliding-window chunk scan    │     │
  │  │  Random cert serials      │  └───────────────────────────────┘     │
  │  └──────────────┬────────────┘                                        │
  └─────────────────┼──────────────────────────────────────────────────── ┘
                    │ HTTP_PROXY, HTTPS_PROXY, NO_PROXY
                    │ NODE_EXTRA_CA_CERTS, NODE_OPTIONS="--import hooks.mjs"
                    │ MessageChannel port for live secrets sync
                    ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │  Child Process  (your app)                                            │
  │                                                                        │
  │  ┌──────────────┐   ┌────────────────────────────────────────────┐    │
  │  │  Your Code   │   │  hooks.mjs  (injected via --import)        │    │
  │  │  + npm deps  │   │                                            │    │
  │  └──────┬───────┘   │  CJS: Module.prototype.require patch       │    │
  │         │ import/   │  ESM: module.register() resolve hook       │    │
  │         │ require   │  process.env Proxy for live secret sync    │    │
  │         └──────────▶│  Wraps child_process + dns modules         │    │
  │                      │  initialize() receives MessagePort         │    │
  │                      └────────────────────────────────────────────┘    │
  └──────────────────────────────────────────────────────────────────────┘
```

---

## What's New in v2.1.0

| Fix                            | Change                                                                              |
|--------------------------------|-------------------------------------------------------------------------------------|
| Native RSA key generation      | TLS cert synthesis reduced from ~200ms to ~5ms using `crypto.generateKeyPairSync`   |
| Sliding-window chunk scanner   | Eliminated O(n²) `Buffer.concat` in the MITM proxy TCP handler                     |
| Shell injection prevention     | CA tooling migrated from `execSync` templates to `execFileSync` argument arrays     |
| RFC 5280-compliant serials     | Certificate serials now use `crypto.randomBytes(20)` instead of `Date.now()`        |
| Real-time ESM loader sync      | `MessageChannel` + `process.env` Proxy broadcasts secret rotations instantly        |
| Automatic `NO_PROXY` injection | Loopback and excluded domains bypass the MITM proxy automatically                   |

---

## License

MIT License. Runs locally with zero telemetry.
