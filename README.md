# envtrap

> [!IMPORTANT]
> **Repository Discontinued**: This repository has been discontinued and migrated to the **EnvTrap** organization at **[https://github.com/EnvTrap](https://github.com/EnvTrap)**, where the package now lives in its own dedicated repository.

A zero-configuration runtime secret leak detector and egress firewall for Node.js.

`envtrap` wraps your Node.js application and intercepts every outbound channel in real time — before secrets, credentials, or sensitive environment variables can be exfiltrated by malicious code, compromised packages, or insider threats.

Unlike static analysis (SAST) tools that scan source code at build time, `envtrap` operates **at execution time** — inspecting actual traffic, subprocesses, DNS queries, and output streams as they happen.

---

## Developer & Architecture Documentation

If you want to understand how the codebase works, how modules are intercepted, or how to contribute, refer to our modular developer guides:

- **[System Architecture](docs/architecture.md)**: High-level design, directory structure layout map, and component responsibilities.
- **[Interception Flow & Runtime Hooks](docs/interception-flow.md)**: ESM loaders, CommonJS require patching, parent-child communication line protocol, and TLS proxy decryption.
- **[SOLID Coding Principles & Standards](docs/coding-principles.md)**: How SOLID is applied, class size and method length constraints, state isolation, and print formatting rules.
- **[Extending envtrap](docs/extending-envtrap.md)**: Step-by-step guides to add a new scan channel, create custom secret loaders, write custom reporters, and add integration tests.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Setup instructions, local testing, build compilation, and PR rules.
- **[Security Policy](SECURITY.md)**: Supported versions and disclosure rules.
- **[License](LICENSE.md)**: MIT License details.

---

## Features

- **HTTPS/HTTP MITM Proxy** (`network` channel, default: `block`): Intercepts outbound traffic, decrypts payloads, and scans request headers, URLs, and bodies for secrets. Local loopback traffic is automatically bypassed via `NO_PROXY`.
- **stdout / stderr Stream Scanning** (`stdout`/`stderr` channels, default: `warn`): Pipes process output streams to scan, redact, and optionally kill execution on leaks.
- **Child Process Env Validation** (`child_process` channel, default: `warn`): Intercepts `spawn`, `exec`, `execFile`, `fork`, and all sync variants to inspect `options.env` for secrets before any OS fork.
- **DNS Interception** (`dns` channel, default: `block`): Detects secrets encoded inside DNS hostname queries and blocks resolver calls for both callback and promise-based APIs.
- **High-Entropy Tunneling Detection**: Identifies potential base64/hex DNS tunneling using Shannon-entropy analysis on each subdomain label.
- **Real-Time Secret Synchronization**: Dynamically-rotated or injected credentials are automatically detected and synced instantly — no restart needed.
- **AI-Safe Redaction**: Raw credential values are never printed. Only their SHA-256 hash prefix is shown in terminal output and reports.

---

## Installation

```bash
# Global install
npm install -g envtrap

# Dev dependency
npm install --save-dev envtrap

# One-off, no install
npx envtrap run node app.js
```

---

## Usage

Prefix your Node.js startup command with `envtrap run`:

```bash
envtrap run node app.js

# Express / Fastify
envtrap run node server.js

# NestJS
envtrap run node dist/main.js

# Next.js (server-side protection)
envtrap run npm run start
```

### CLI Flags

```bash
# Custom .env file
envtrap run --env-file .env.production node app.js

# Disable HTTPS MITM proxy
envtrap run --no-mitm node app.js

# Verbose debug output
envtrap run --verbose node app.js

# Quiet mode — suppress alerts, show summary only
envtrap run --quiet node app.js

# Write structured JSONL events
envtrap run --log-file logs/envtrap.jsonl node app.js

# Validate envtrap.json before running
envtrap check
```

---

## Configuration (`envtrap.json`)

Create an optional `envtrap.json` in your project root. All fields are optional — defaults are secure out of the box.

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

### Channel Modes

- **`block`**: Log leak event, redact secrets, and kill the process/connection immediately.
- **`warn`**: Log leak event, redact secrets, and allow execution to continue.
- **`off`**: Turn off scanning for this channel entirely.
