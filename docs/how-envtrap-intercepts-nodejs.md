# How EnvTrap Gains Access to a Node.js Application

A plain-English, developer-friendly guide explaining exactly how EnvTrap hooks into your Node.js code from scratch without requiring you to change a single line of your application.

---

## 1. The Core Secret: The "Wrapper" Pattern

EnvTrap does not magically hack into a running server from the outside. 

Instead, it uses the **Parent-Child Process Wrapper** pattern.

When you type:
```bash
envtrap run node app.js
```

You are not running `node app.js` directly. 

You are launching **EnvTrap first**. EnvTrap sets up its security traps and proxy servers, prepares the environment, and then launches your `node app.js` as its **child process**, with custom hooks pre-loaded into Node's brain before your code starts.

Think of it like hiring an undercover security escort: before your application steps into the room, the escort has already wired the room with sensors and cameras.

---

## 2. Step-by-Step: What Happens from the Very First Millisecond

Here is the exact lifecycle of what happens from the moment you hit Enter:

```
[ You run: envtrap run node app.js ]
                  |
                  v
+-------------------------------------------------------------+
| Phase 1: EnvTrap Boots Up (The Parent Supervisor)            |
| 1. Reads envtrap.json and your .env file                    |
| 2. Identifies all secret tokens                             |
| 3. Boots a local in-memory HTTPS Proxy on a random port     |
| 4. Generates a temporary local Root SSL Certificate Authority|
+-------------------------------------------------------------+
                  |
                  v
+-------------------------------------------------------------+
| Phase 2: Preparing the Child Process Environment             |
| Sets environment variables for your app:                    |
| - NODE_OPTIONS="--import /path/to/hooks.mjs"                |
| - HTTP_PROXY="http://127.0.0.1:45678"                       |
| - HTTPS_PROXY="http://127.0.0.1:45678"                      |
| - NODE_EXTRA_CA_CERTS="/tmp/envtrap-ca.crt"                 |
| - __ENVTRAP_SECRETS_MAP__='{"STRIPE_KEY":"sk_live_123"}'   |
+-------------------------------------------------------------+
                  |
                  v
+-------------------------------------------------------------+
| Phase 3: Spawning Your App (child_process.spawn)            |
| Node.js boots up your app, but notices --import hooks.mjs   |
| Node loads EnvTrap's hooks BEFORE reading app.js!           |
+-------------------------------------------------------------+
                  |
                  v
+-------------------------------------------------------------+
| Phase 4: Inside Your App (The Traps are Set)                 |
| 1. ESM Loader Hook intercepts import from 'node:dns'        |
| 2. CJS Hook replaces require('dns') and require('child_process')|
| 3. Hijacks process.stdout.write & process.stderr.write      |
| 4. process.env is wrapped in a Proxy to watch for changes   |
+-------------------------------------------------------------+
                  |
                  v
+-------------------------------------------------------------+
| Phase 5: Your app.js Finally Runs                           |
| Your code runs normally at full speed.                      |
| Any leak attempts hit the traps and get blocked or redacted!|
+-------------------------------------------------------------+
```

---

## 3. The 5 Specific Mechanisms EnvTrap Uses to Gain Control

How does EnvTrap actually intercept different parts of Node.js? It uses five distinct built-in Node.js mechanisms:

---

### Mechanism 1: `NODE_OPTIONS="--import hooks.mjs"` (Pre-Execution Injection)

Node.js has a built-in environment variable called `NODE_OPTIONS`. Whatever flags you put in `NODE_OPTIONS`, Node treats as if you typed them directly into the command line.

EnvTrap sets:
```bash
NODE_OPTIONS="--import /path/to/dist/hooks/hooks.mjs"
```

The `--import` flag tells Node.js:
> *"Before you parse, compile, or execute `app.js`, load and execute `hooks.mjs` first."*

This is the master key. It guarantees that EnvTrap has full control of the JavaScript runtime before any of your dependencies (like Express, Axios, or third-party npm packages) even wake up.

---

### Mechanism 2: ESM Customization Hooks (Intercepting `import from 'node:dns'`)

In modern JavaScript (ES Modules), you write:
```javascript
import dns from 'node:dns';
```

ES Modules are frozen and immutable in Node.js. You cannot simply overwrite `dns.lookup = ...` from the outside.

So how does EnvTrap intercept it?
Node.js provides a feature called **Module Customization Hooks** (`module.register`).

In `src/hooks/hooks.mjs`, EnvTrap registers two hooks:
1. `resolve(specifier, context)`:
   Whenever any file in your project imports `'dns'` or `'node:dns'`, Node asks EnvTrap: *"Where should I get this module from?"*
   EnvTrap intercepts the request and says:
   *"Don't load the real Node DNS module. Load `envtrap:dns` instead."*

2. `load(url, context)`:
   When Node tries to load `envtrap:dns`, EnvTrap serves a virtual module (`src/hooks/virtual/dns.mjs`).
   This virtual module exports all the normal DNS functions (`lookup`, `resolve`, `promises`, etc.), but wraps each one in security checks first!

To your application, it looks and behaves 100% like the official Node.js `node:dns` module, but every call is monitored.

---

### Mechanism 3: CommonJS Monkeypatching (Intercepting `require('child_process')`)

Many npm packages still use CommonJS:
```javascript
const cp = require('child_process');
```

For CommonJS, Node has an internal object called `Module.prototype.require`. Every single `require()` statement in your app passes through this function.

In `src/hooks/hooks.mjs`, EnvTrap wraps `Module.prototype.require`:
```javascript
const originalRequire = Module.prototype.require;

Module.prototype.require = function(id) {
  // If the code asks for child_process, give them our protected wrapper!
  if (id === 'child_process' || id === 'node:child_process') {
    return wrappedChildProcess;
  }
  // If the code asks for dns, give them our protected wrapper!
  if (id === 'dns' || id === 'node:dns') {
    return wrappedDns;
  }
  // Otherwise, load the library normally
  return originalRequire.apply(this, arguments);
};
```

When malicious or accidental code calls `cp.spawn('sh', ['script.sh'])`, it is actually calling EnvTrap's wrapper, which inspects the environment and arguments before deciding whether to allow the real OS call.

---

### Mechanism 4: Global Stream Hijacking (Intercepting `stdout` and `stderr`)

When your code calls `console.log("User config:", process.env)`:
Behind the scenes, `console.log` is just a helper that calls `process.stdout.write()`.

In Node.js, `process.stdout` and `process.stderr` are standard JavaScript writable streams attached to the global `process` object.

EnvTrap simply replaces the `.write` method on both streams:
```javascript
const origStdout = process.stdout.write.bind(process.stdout);

process.stdout.write = function(chunk, encoding, callback) {
  // Check if this text contains any secret keys
  const sanitized = redactSecretsIfFound(chunk);
  // Send the clean version to the real terminal
  return origStdout(sanitized, encoding, callback);
};
```

If a secret is about to be printed to the screen, EnvTrap catches the string, replaces the secret with a safe hash like `[REDACTED: SHA256:abcd1234]`, and only prints the redacted version.

---

### Mechanism 5: The Local MITM Proxy (Intercepting Outbound HTTPS)

How does EnvTrap stop an HTTP request sent via `axios.post('https://external-api.com')` without touching Axios code?

It uses standard network proxy environment variables:
1. When EnvTrap starts, it spins up a lightweight HTTP/HTTPS proxy server right on your computer on `127.0.0.1` (localhost) using a random available port.
2. It sets:
   ```bash
   HTTP_PROXY="http://127.0.0.1:45678"
   HTTPS_PROXY="http://127.0.0.1:45678"
   ```
3. Most HTTP client libraries (Axios, Got, Request, Node's `https` module) automatically read `HTTP_PROXY` and route their connections through this local proxy.
4. Because HTTPS is encrypted, the proxy needs to see inside the request. EnvTrap creates an in-memory Root Certificate Authority (CA) and tells Node.js to trust it via:
   ```bash
   NODE_EXTRA_CA_CERTS="/tmp/envtrap-ca.crt"
   ```
5. When your app makes an HTTPS call, your app connects to EnvTrap's proxy. EnvTrap decrypts the request on the fly, checks the headers and body for secrets, and:
   - If clean: forwards it to the real external destination.
   - If a secret is leaking: immediately kills the connection before data leaves your computer.

---

## 4. Summary: How Each Channel is Hooked

| Channel | What You Code In Your App | How EnvTrap Gains Access |
| :--- | :--- | :--- |
| **Terminal Logs** (`stdout`, `stderr`) | `console.log()`, `console.error()` | Replaces `process.stdout.write` and `process.stderr.write` |
| **DNS Resolution** (`dns`) | `import 'node:dns'` or `require('dns')` | ESM loader hook redirects to `envtrap:dns`; CJS monkeypatches `Module.prototype.require` |
| **Child Processes** (`child_process`) | `spawn()`, `exec()`, `fork()` | Replaces exported functions via `Module.prototype.require` and ESM loader virtual modules |
| **Outbound HTTPS** (`network`) | `fetch()`, `axios.get()`, `https.request()` | Injects `HTTP_PROXY`, `HTTPS_PROXY`, and local Root CA into child process environment |
| **Runtime Secret Changes** | `process.env.NEW_KEY = 'val'` | Wraps `process.env` in a JavaScript `Proxy` to detect new or deleted variables in real time |

---

## 5. Why This Design is Powerful

1. **Zero Code Changes**: Developers do not need to import `envtrap` in their source files or refactor their code.
2. **Framework Agnostic**: Works identically whether you use Express, Fastify, NestJS, Next.js, or plain Node.js.
3. **Execution Priority**: Because `--import` runs before user code, security rules are active before any untrusted third-party npm package can run its first line of code.
