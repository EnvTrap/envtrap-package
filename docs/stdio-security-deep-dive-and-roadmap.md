# EnvTrap Terminal Streams (Stdio) Deep Dive: Architecture, Node.js Internals, and Threat Model

A plain-English guide explaining how credentials leak through terminal logs and console streams, how Node.js streams work under the hood, how EnvTrap redacts secrets in real time, and what we are building next.

---

## 1. What is the Stdio Channel and Why Does it Matter?

### The Accidental Leak Vector
Unlike DNS or network exfiltration which are usually caused by malicious packages, terminal leaks (`stdout` and `stderr`) are most often caused by **accidental developer mistakes** or over-eager debugging libraries:
```javascript
// A database error occurs, and the library dumps the full connection string:
console.error("Database connection failed:", connectionConfig);
// Or a debug statement logs full headers:
console.log("Outbound request headers:", req.headers);
```

### Where Does Terminal Output Go?
In modern cloud and enterprise software development:
1. **CI/CD Build Logs**: Terminal output gets saved into public or shared CI/CD build logs (GitHub Actions, GitLab CI, CircleCI).
2. **Cloud Log Aggregators**: Terminal output is streamed to Datadog, AWS CloudWatch, Loggly, or Splunk where hundreds of developers or contractors have read access.
3. **Third-Party Crash Reporters**: Uncaught exceptions dumped to stderr are indexed by Sentry, Bugsnag, or Rollbar.
4. If an API key or database password is printed to `stdout` or `stderr`, it is immediately indexed in plain text across multiple permanent storage systems.

---

## 2. Node.js Internals: How `stdout` and `stderr` Work

### Node.js Internal 1: File Descriptors 1 and 2
At the operating system level, every running process has three standard POSIX file descriptors:
- `FD 0`: Standard Input (`stdin`)
- `FD 1`: Standard Output (`stdout`)
- `FD 2`: Standard Error (`stderr`)

### Node.js Internal 2: `process.stdout` and `process.stderr`
In Node.js:
- `process.stdout` and `process.stderr` are instances of `net.Socket` (when pointing to a terminal TTY or pipe) or `fs.SyncWriteStream`.
- When you execute `console.log("hello")`, the `console` module formats arguments via `util.format()`, appends `\n`, and calls:
  ```javascript
  process.stdout.write("hello\n");
  ```

### Node.js Internal 3: The Libuv Event Loop and Stream Buffering
`process.stdout.write()` is non-blocking on Unix when pointing to a pipe. Data is pushed into an internal Libuv stream queue.
If your application prints 10 megabytes of logs at once, Node breaks the data into chunks (usually 16KB or 64KB buffers) and sends them across the stream asynchronously.

### Node.js Internal 4: Parent-Child Stdio Piping
When EnvTrap runs your application (`ChildProcessManager.ts`), it uses:
```typescript
stdio: ['inherit', 'pipe', 'pipe']
```
This tells the operating system:
- Connect `stdin` directly to your keyboard.
- Replace `stdout` (FD 1) and `stderr` (FD 2) with **operating system pipes** connected directly to EnvTrap's supervisor process.
- The child application **cannot write directly to your screen**. Everything must pass through EnvTrap's interceptor first.

---

## 3. How EnvTrap Intercepts and Redacts Stdio

EnvTrap uses a **dual-layer redaction architecture**:

```
+-------------------------------------------------------------------------------+
| Monitored Application (Child Process)                                         |
|                                                                               |
|   console.log("Token:", secret)                                               |
|         │                                                                     |
|         ▼                                                                     |
|   process.stdout.write (hooks.mjs Layer 1)                                    |
|   - Zero-Overhead Fast-Path: If no exclusions configured, skips stack capture |
|   - If caller is in exclusions.paths (e.g. test/**):                          |
|     -> Pre-redacts secret to [REDACTED: PATH_EXCLUDED]                        |
+---------│---------------------------------------------------------------------+
          │
          │ Operating System Pipe (FD 1)
          ▼
+-------------------------------------------------------------------------------+
| EnvTrap Supervisor Process (StdioHandler.ts Layer 2)                          |
|                                                                               |
|  1. handleStdout(chunkBuffer)                                                 |
|  2. Scanner.ts scans chunk for active secrets                                 |
|                                                                               |
|  [Decision Gate]                                                              |
|   ├── Leak found & mode === 'block':                                          |
|   │     -> Sends SIGTERM to child process immediately. Execution stopped.     |
|   └── Leak found & mode === 'warn':                                           |
|         -> OutputRedactor.ts replaces secret with SHA-256 fingerprint:        |
|            "Bearer [REDACTED: SHA256:56018fa5]"                               |
|         -> Writes redacted string to real process.stdout.                     |
|         -> Logs alert box to stderr and records incident in report.           |
+-------------------------------------------------------------------------------+
```

### 3.1 Layer 1: In-Child Pre-Redaction (`src/hooks/hooks.mjs`)
Inside the application process:
- EnvTrap wraps `process.stdout.write` and `process.stderr.write`.
- If `exclusions.paths` is configured, it checks the caller file using `getCallerFile()`.
- If the output originates from a test file or mock runner, it sanitizes the string before writing it to the pipe.
- **v3.1 Zero-Overhead Fast-Path**: If `exclusions.paths` is empty, or the stream chunk does not contain any secret, EnvTrap completely skips capturing the V8 stack trace.

### 3.2 Layer 2: Supervisor Real-Time Interception (`src/cli/StdioHandler.ts`)
In the supervisor process:
- `StdioHandler` receives raw chunks from the child process.
- It scans the text against the secret registry.
- If a secret is detected:
  - In **`warn`** mode (default): `OutputRedactor` replaces every instance of the raw secret with its SHA-256 hash prefix (`[REDACTED: SHA256:xxxx]`). The raw secret **never touches your terminal screen or CI logs**.
  - In **`block`** mode: The supervisor immediately sends `SIGTERM` to the child process to prevent any further leaks.

---

## 4. Current Flaws & Bottlenecks in EnvTrap's Stdio Code

### Flaw 1: Missing Stream Backpressure (Issue #12)
In `ChildProcessManager.ts`:
```typescript
this.child.stdout?.on('data', (chunk) => { this.handler.handleStdout(chunk, ...); });
```
If the child process produces gigabytes of logs per second faster than `Scanner` and `OutputRedactor` can process them, Node buffers incoming chunks into memory without applying backpressure, leading to high heap consumption.

### Flaw 2: Redundant Redaction Pass on Clean Streams (Issue #23)
Previously, `OutputRedactor.redact()` executed a full string replacement loop across all secrets even when `Scanner.scan()` already verified the chunk was clean. Fixed in v3.1 to only redact when `result.leaked === true`.

### Flaw 3: Stderr Protocol Message Collision (Issue #60)
The child process sends IPC alerts (like child process leaks and DNS warnings) to the supervisor by printing text prefixes to `stderr` (e.g. `[envtrap] DNS leak:`). If the application itself logs text containing that string, the supervisor's `HookMessageParser` can misinterpret it as a protocol command.

---

## 5. Technical Roadmap: How We Are Upgrading the Stdio Channel

```
                     Child Stdio Output Chunk
                                 │
                                 ▼
          +---------------------------------------------+
          | Step 1: Flow Control Backpressure           |
          | If supervisor queue exceeds highWaterMark,  |
          | call child.stdout.pause() until flushed.    |
          +---------------------------------------------+
                                 │
                                 ▼
          +---------------------------------------------+
          | Step 2: Dedicated IPC Channel               |
          | Move protocol messages off stderr to a      |
          | dedicated IPC channel or domain socket.     |
          +---------------------------------------------+
                                 │
                                 ▼
          +---------------------------------------------+
          | Step 3: Zero-Copy String Redactor           |
          | Single-pass multi-secret redaction using    |
          | index offsets instead of split().join().    |
          +---------------------------------------------+
                                 │
                                 ▼
                     Real Terminal Output
```

---

## 6. Configuration Reference in `envtrap.json`

```json
{
  "channels": {
    "stdout": "warn",
    "stderr": "warn"
  },
  "exclusions": {
    "paths": ["test/**", "**/*.spec.ts", "scripts/seed.ts"]
  }
}
```

---

## 7. Summary Table

| Problem | How It Works Now | What Was Wrong | How We Are Fixing It |
|:---|:---|:---|:---|
| **Console Leaks** | Pipes stdout/stderr to parent | Plain secrets appear in cloud logs | Real-time SHA-256 fingerprint redaction |
| **High Log Volume** | Emits on every `data` event | No backpressure; memory buffers unbounded | Add `pause()`/`resume()` stream flow control (Issue #12) |
| **Stack Lag** | Checks caller on every write | `new Error().stack` added lag to console | Fast-path bypass when exclusions empty (v3.1) |
| **Protocol Collision**| Strings printed to stderr | App logging `[envtrap]` could fake alerts | Migrate to Node.js dedicated IPC channel (Issue #60) |\n