# envtrap

A zero-configuration runtime secret leak detector and egress firewall for Node.js.

`envtrap` wraps your Node.js application and intercepts every outbound channel in real time — before secrets, credentials, or sensitive environment variables can be exfiltrated by malicious code, compromised packages, or insider threats.

Unlike static analysis (SAST) tools that scan source code at build time, `envtrap` operates **at execution time** — inspecting actual traffic, subprocesses, DNS queries, and output streams as they happen.

---

## Developer & Architecture Documentation

If you want to understand how the codebase works, how modules are intercepted, or how to contribute, refer to our modular developer guides:

- **[System Architecture](https://github.com/EnvTrap/envtrap-package/blob/main/docs/architecture.md)**: High-level design, directory structure layout map, and component responsibilities.
- **[Interception Flow & Runtime Hooks](https://github.com/EnvTrap/envtrap-package/blob/main/docs/interception-flow.md)**: ESM loaders, CommonJS require patching, parent-child communication line protocol, and TLS proxy decryption.
- **[SOLID Coding Principles & Standards](https://github.com/EnvTrap/envtrap-package/blob/main/docs/coding-principles.md)**: Details on Clean Architecture boundaries, SOLID design patterns, stateless execution, and testability design guidelines.
- **[Extending envtrap](https://github.com/EnvTrap/envtrap-package/blob/main/docs/extending-envtrap.md)**: Step-by-step guides to add a new scan channel, create custom secret loaders, write custom reporters, and add integration tests.
- **[Contributing Guidelines](https://github.com/EnvTrap/envtrap-package/blob/main/CONTRIBUTING.md)**: Setup instructions, local testing, build compilation, and PR rules.
- **[Security Policy](https://github.com/EnvTrap/envtrap-package/blob/main/SECURITY.md)**: Supported versions and disclosure rules.
- **[License](https://github.com/EnvTrap/envtrap-package/blob/main/LICENSE.md)**: MIT License details.

---

## Interception Channels

`envtrap` intercepts leaks across five distinct runtime vectors:

* **HTTPS/HTTP MITM Proxy** (`network` channel): Routes outbound TCP connections through an ephemeral, in-memory loopback proxy. Intercepts request headers, URLs, and payloads, verifying them before forwarding. Ephemeral TLS certificates are generated on-the-fly and trusted by injecting a temporary Root CA into `NODE_EXTRA_CA_CERTS`.
* **Standard Output Scanning** (`stdout` / `stderr` channels): Hooks standard output streams to search for registered credentials. Matches are redacted using a secure SHA-256 fingerprint placeholder.
* **Subprocess Environment Check** (`child_process` channel): Hooks Node.js process creation modules (`child_process.spawn`, `exec`, `fork`, and their synchronous equivalents) at the binding layer to prevent sensitive credentials from being inherited by child processes.
* **DNS Resolution Auditing** (`dns` channel): Hooks the core `node:dns` module to detect secrets encoded directly inside hostname resolution queries.
* **High-Entropy Label Detection**: Uses Shannon entropy analysis on subdomain labels to automatically flag potential base64/hex DNS tunneling vectors.

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

Prefix your existing Node.js startup command with `envtrap run`:

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
# Custom .env file path
envtrap run --env-file .env.production node app.js

# Disable HTTPS MITM proxy (bypasses network interception)
envtrap run --no-mitm node app.js

# Verbose output (logs cert issuance and network handshake information)
envtrap run --verbose node app.js

# Quiet mode (suppress terminal alerts, prints exit summary only)
envtrap run --quiet node app.js

# Append JSONL events to a custom file
envtrap run --log-file logs/envtrap.jsonl node app.js

# Verify the syntax of envtrap.json
envtrap check
```

---

## Configuration (`envtrap.json`)

You can customize rules by creating an `envtrap.json` file in your project root:

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

- **`block`**: Halts execution, closes the network stream, or interrupts the system command immediately when a secret leak is detected.
- **`warn`**: Emits a warning log detailing the leak event, redacts the matched content, and allows the operation to proceed.
- **`off`**: Disables the corresponding interception channel entirely.

### Exclusions & Subdomain Bypasses
- **`domains`**: Bypasses network interception for specific target hosts. These domains are automatically appended to the environment's `NO_PROXY` parameters.
- **`paths`**: Glob patterns targeting source files. Detections originating from source code inside these paths are ignored.
