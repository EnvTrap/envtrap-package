# Interception Flow & Runtime Hooks

This document details the mechanics of how `envtrap` intercepts module loaders, network requests, DNS queries, and subprocesses at runtime.

---

## 1. Parent/Child Communication Protocol

Because Node.js ESM customization hooks run in a separate thread (the loader thread) and cannot block synchronous code, communicating leaks back to the parent CLI must occur over a reliable, out-of-band channel.

`envtrap` uses the standard error (`stderr`) stream with a custom line-based protocol to route leak signals:

1. When a hook (like `node:dns`) detects that a hostname contains a secret value, it writes a structured message to `process.stderr`:
   ```
   [envtrap] DNS leak: secret "STRIPE_SECRET_KEY" found in lookup of: prefix.sk_test_123.com
   ```
2. The Parent process (`ChildProcessManager` + `StdioHandler`) intercepts all data on `stderr`.
3. The parent routes these logs through `HookMessageParser`.
4. If a match is found:
   - The parent registers the leak in the parent's stateful `Scanner`.
   - The parent runs the appropriate reporter (e.g. print warning, write report).
   - If the channel mode is `block`, the parent calls `.kill('SIGTERM')` on the child.
5. If no match is found, the parent treats it as normal application `stderr` output, redacts any secrets found in the line, and prints it to the terminal standard error.

---

## 2. ESM Custom Loader Hooks

Node.js allows customizing the resolution and loading of ES modules via customization hooks (`resolve` and `load`) injected with `--import`.

### Module Resolution (`resolve` hook)
When a module requests a core library like `node:child_process` or `node:dns`, the resolve hook intercepts the request:

```javascript
export async function resolve(specifier, context, nextResolve) {
  if (CP_SPECIFIERS.has(specifier)) {
    return { url: 'envtrap:child_process', shortCircuit: true };
  }
  if (DNS_SPECIFIERS.has(specifier)) {
    return { url: 'envtrap:dns', shortCircuit: true };
  }
  return nextResolve(specifier, context);
}
```

This maps import specifiers directly to our virtual protocols (`envtrap:*`).

### Module Loading (`load` hook)
When Node.js attempts to load an `envtrap:` protocol URL, the load hook intercepts the loader, reads our pre-written virtual wrapper code from disk (`src/hooks/virtual/dns.mjs`), replaces the shared import path placeholder (`__HOOKS_SHARED_URL__`), and returns it:

```javascript
export async function load(url, context, nextLoad) {
  if (url === 'envtrap:dns') {
    const source = fs.readFileSync(join(__hooksDir, 'virtual', 'dns.mjs'), 'utf-8')
      .replaceAll('__HOOKS_SHARED_URL__', sharedUrl);
    return { format: 'module', shortCircuit: true, source };
  }
  return nextLoad(url, context);
}
```

---

## 3. CommonJS Interception

Because older Node.js packages might still use `require()`, the customization hooks inject a monkeypatch onto `module` in the main thread:

1. It intercepts `Module.prototype.require`.
2. When `require('child_process')` or `require('dns')` is executed:
   - Instead of returning the raw core module, `envtrap` wraps it in a proxy.
   - The proxy wraps exported functions (like `dns.lookup` or `child_process.exec`) with the exact same scan checks used in the ESM virtual modules.
3. This ensures CommonJS dependencies get the exact same level of secret leak checks as native ES Modules.

---

## 4. HTTPS/HTTP MITM Decryption

When network channels are active, `envtrap` starts a local proxy server and configures the environment to route child traffic through it:

1. **Proxy Injection**: `HTTP_PROXY`, `HTTPS_PROXY`, and `NODE_EXTRA_CA_CERTS` are set in the child process's environment variables.
2. **Local CA Registration**: On startup, an ephemeral 2048-bit Root CA certificate is generated in memory. The public cert is written to a temporary file on disk, which is injected via `NODE_EXTRA_CA_CERTS` so the child process trusts it implicitly.
3. **HTTP Requests**: Handled by `HttpHandler`, which intercepts and scans the body/headers/URL before forwarding the request to the upstream target.
4. **HTTPS CONNECT Handshake**:
   - When a secure request goes through, the child sends an HTTP `CONNECT` command.
   - `ConnectHandler` intercepts this, extracts the target host (e.g. `api.stripe.com`), and generates a dynamic domain certificate signed by our root CA.
   - The proxy responds to the child with `200 Connection Established`.
   - The proxy starts an in-memory TLS server using the dynamically generated certificate.
   - The child process performs a TLS handshake with this loopback TLS server, trusting it because the root CA is registered in `NODE_EXTRA_CA_CERTS`.
5. **Decryption and Scan**:
   - `TlsInterceptor` receives the decrypted data sent by the child.
   - The decrypted chunk is scanned for secrets. If a leak is found and `network` is in `block` mode, the connection is instantly severed and the child process is terminated.
   - If clear, `UpstreamConnector` forwards the request over a real TLS socket to the upstream server.

---

## 5. Live Secret Synchronization

If the application rotates secrets during execution, `envtrap` updates the scanner without requiring a reload:

1. **Proxying process.env**: The main thread wraps `process.env` in a JavaScript `Proxy`.
2. **Detection**: Whenever a new environment variable is set at runtime, `looksLikeSecret` analyzes the value.
3. **Message Syncing**:
   - When a valid secret is found, the main thread posts a message through a `MessageChannel` port established during `initialize()`.
   - The ESM loader thread listens to this channel and updates its local `secretsMap` instantly, ensuring that all future module resolutions and DNS checks immediately scan for the new secret.
