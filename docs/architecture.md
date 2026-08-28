# System Architecture

This document describes the high-level architecture of `envtrap` and how its components interact across parent-child process boundaries to intercept secret leaks at runtime.

---

## Process Boundary Overview

`envtrap` splits responsibilities across two Node.js execution threads/processes:

1. **The Parent CLI Process**: Spawns your application, sets up the interception environment, acts as a local HTTPS/HTTP MITM proxy, monitors `stdout`/`stderr` streams, redacts credential values in real time, and writes leak summaries on exit.
2. **The Child Process (Your App)**: Runs under Node.js with a custom ESM loader hook and CommonJS hook injected via `--import`. These hooks monitor low-level runtime interfaces (`node:child_process`, `node:dns`, `process.env`) and report matches back to the parent.

```
+-------------------------------------------------------------------------+
| envtrap CLI (Parent Process)                                            |
|                                                                         |
|  +---------------------------+       +-------------------------------+  |
|  | MITM TLS Proxy Server     |       | Stream Scanner                |  |
|  | (Intercepts request       |       | (Scans & redacts              |  |
|  |  headers/URLs/bodies)     |       |  stdout/stderr streams)       |  |
|  +──────────────┬────────────+       +───────────────────────────────+  |
+─────────────────┼───────────────────────────────────────────────────────+
                  | Env variables: HTTP_PROXY, NODE_EXTRA_CA_CERTS,
                  | NODE_OPTIONS="--import hooks.mjs"
                  | stderr communication pipe
                  v
+-------------------------------------------------------------------------+
| Monitored Node.js Runtime (Child Process)                               |
|                                                                         |
|  +--------------------+        +----------------─────────────────────+  |
|  | Application Code   | ---->  | hooks.mjs (Custom Loader Thread)    |  |
|  | (Express, Nest,    |        |                                     |  |
|  |  Next.js, etc.)    |        |  * Resolves modules to envtrap:*    |  |
|  +--------------------+        |  * Monkeypatches CJS require        |  |
|                                |  * Intercepts node:child_process    |  |
|                                |  * Intercepts node:dns              |  |
|                                +-------------------------------------+  |
+-------------------------------------------------------------------------+
```

---

## Directory Layout Map

The code is strictly partitioned by domain layers following SOLID Clean Architecture rules:

```
src/
├── types.ts                    # Shared entity schemas (Secret, LeakEvent, ScanResult)
│
├── ports/                      # Core abstractions (Dependency Inversion)
│   ├── IScanner.ts             # Scanning engine interface
│   ├── IReporter.ts            # High-level listener interface
│   └── ISecretSource.ts        # Input secret source interface
│
├── domain/                     # Pure logic domain objects
│   ├── ContentClamp.ts         # Protection against scanning huge files (>1MB)
│   ├── DedupCache.ts           # TTL-based leak alert deduplicator
│   ├── SecretMatcher.ts        # Substring scans & entropy candidate checkers
│   └── OutputRedactor.ts       # Hash-based credential redaction (SHA-256)
│
├── config/                     # Configuration management
│   ├── ConfigTypes.ts          # Configurations & Default schemas
│   ├── ConfigLoader.ts         # Coordinates reading config from disk
│   ├── ConfigMerger.ts         # Merges config objects safely
│   ├── ConfigValidator.ts      # Strictly validates configurations
│   ├── PathMatcher.ts          # Evaluates path glob exclusions
│   └── Version.ts              # Resolves package version dynamically from package.json
│
├── secrets/                    # Secret loaders (Adapters)
│   ├── EnvSecretSource.ts      # Loads valid secrets from environment variables
│   ├── DotEnvSecretSource.ts   # Loads valid secrets from file-based .env
│   └── SecretSourceComposer.ts # Deduplicates and aggregates multiple sources
│
├── reporting/                  # Output & Event Logging (Adapters)
│   ├── ILeakReporter.ts        # Base interface for individual log outputs
│   ├── CompositeReporter.ts    # Multi-reporter dispatcher
│   ├── LeakAlertPrinter.ts     # Clean, emoji-free stdout printer
│   ├── RunSummaryPrinter.ts    # Grouped exit leak summary compiler
│   ├── BannerPrinter.ts        # Minimalist startup text printer
│   ├── FileEventLogger.ts      # Structured JSONL logging
│   └── ReportWriter.ts         # End-of-run JSON report writer
│
├── mitm/                       # HTTPS/HTTP Interception (Adapters)
│   ├── CertificateAuthority.ts # In-memory Root CA signer
│   ├── SystemCaTrust.ts        # Injects/Removes Root CA from OS trust stores
│   ├── MitmServer.ts           # Proxy server loopback coordinator
│   ├── HttpHandler.ts          # Plain HTTP request parsing
│   ├── ConnectHandler.ts       # CONNECT tunnel creation & SNI handshake
│   ├── TlsInterceptor.ts       # Decrypts and buffers TLS traffic
│   └── UpstreamConnector.ts    # Pipes intercepted request to true server
│
├── cli/                        # CLI & Child Orchestration
│   ├── index.ts                # Commander.js CLI entrypoint
│   ├── runner.ts               # Legacy runner action wrapper
│   ├── RunCommandBuilder.ts    # Assembles SOLID classes into RunCommand
│   ├── RunCommand.ts           # Orchestrates child lifetime
│   ├── ChildProcessManager.ts  # Spawns process and manages pipes
│   ├── StdioHandler.ts         # Intercepts stdout/stderr, routes protocol
│   ├── HookMessageParser.ts    # Decodes stderr communication messages
│   └── ChildEnvBuilder.ts      # Sets up child environment variables
│
└── hooks/                      # Custom Runtime Hooks
    ├── hooks.mjs               # Node.js ESM resolve, load and initialize hooks
    ├── shared.mjs              # Common loader tools (entropy, paths)
    └── virtual/                # Mocked Node.js core library files
        ├── child-process.mjs   # Intercepted subprocess APIs
        └── dns.mjs             # Intercepted DNS resolver APIs
```

---

## Component Roles

### The Domain Layer
Core business rules like `SecretMatcher` and `OutputRedactor` are written as pure classes containing no side-effects (no file systems, no console logging, no networks). This ensures that core scanning operations are highly deterministic and can be tested in isolation.

### The Ports Layer
All adapters communicate with the scanner and logger through interface abstractions (`IScanner`, `IReporter`, `ISecretSource`). For example, the `MitmServer` knows nothing about how secrets are matching or what is being logged; it only knows it can call `.scan()` on an `IScanner` instance and gets a `ScanResult` in response.

### The Adapters Layer
This contains all implementations of ports, OS management, network proxies, and CLI parameters. Because these depend on the interfaces defined in the ports layer, they can be added, deleted, or refactored with zero impact on the core domain layer.
