# Extending envtrap

This document is a developer's guide on how to add new monitoring channels, implement custom secret sources, write new reporters, and add integration tests to `envtrap`.

---

## 1. Adding a New Monitoring Channel

Suppose you want to add a new channel called `file_write` to monitor if secrets are written to disk.

### Step 1: Update type definitions
Add the new channel to the `ChannelName` type union in `src/types.ts`:
```typescript
export type ChannelName = 'stdout' | 'stderr' | 'network' | 'child_process' | 'dns' | 'file_write';
```

### Step 2: Update Configuration
Add `file_write` to `ChannelConfig` in `src/config/ConfigTypes.ts`:
```typescript
export interface ChannelConfig {
  stdout: ChannelMode;
  stderr: ChannelMode;
  network: ChannelMode;
  child_process: ChannelMode;
  dns: ChannelMode;
  file_write: ChannelMode;
}
```
Update `DEFAULT_CONFIG` with the default state for your channel:
```typescript
export const DEFAULT_CONFIG: EnvtrapConfig = {
  channels: {
    stdout: 'warn',
    stderr: 'warn',
    network: 'block',
    child_process: 'warn',
    dns: 'block',
    file_write: 'warn', // our new channel
  },
  ...
};
```
Finally, update the validators in `src/config/ConfigValidator.ts` so `file_write` is accepted as a valid channel key.

### Step 3: Implement Interceptor Hook
Create a wrapper for `node:fs` module in `src/hooks/virtual/fs.mjs` that checks target contents before writing:
```javascript
import fs from 'node:fs';

export function writeFileSync(file, data, options) {
  // Check if data contains secrets, notify parent via process.stderr if found
  // ...
  return fs.writeFileSync(file, data, options);
}
```
Register the virtual module in `src/hooks/hooks.mjs` resolve/load hooks.

---

## 2. Implementing a Custom Secret Provider

By default, `envtrap` loads secrets from `process.env` and `.env`. You can add a new source (e.g. AWS Secrets Manager or HashiCorp Vault) by implementing `ISecretSource`.

### Step 1: Create the Source Class
Create a new file `src/secrets/VaultSecretSource.ts`:
```typescript
import type { ISecretSource } from '../ports/ISecretSource.js';
import type { Secret } from '../types.js';

export class VaultSecretSource implements ISecretSource {
  constructor(private readonly client: any) {}

  load(): Secret[] {
    // Read secrets from your vault client
    const secrets = this.client.getSync('secret/data/app');
    return Object.entries(secrets).map(([name, value]) => ({
      name,
      value: value as string,
      source: 'vault' as const
    }));
  }
}
```

### Step 2: Register the Source
Instantiate and add your new source to the `SecretSourceComposer` inside `src/cli/RunCommandBuilder.ts`:
```typescript
const vaultSource = new VaultSecretSource(vaultClient);
const composer = new SecretSourceComposer([envSource, dotEnvSource, vaultSource]);
```

---

## 3. Implementing a Custom Leak Reporter

To output leak alerts to another service (like a local log collector or syslog daemon), implement the `ILeakReporter` interface.

### Step 1: Create the Reporter
Create `src/reporting/SyslogReporter.ts`:
```typescript
import type { ILeakReporter } from './ILeakReporter.js';
import type { LeakEvent } from '../types.js';

export class SyslogReporter implements ILeakReporter {
  report(event: LeakEvent): void {
    // Format and send the leak metadata to syslog
    const message = `[envtrap] LEAK: ${event.secret.name} on ${event.channel}`;
    sendToSyslog(message);
  }
}
```

### Step 2: Register the Reporter
Add your reporter to the `CompositeReporter` in `src/cli/RunCommandBuilder.ts`:
```typescript
const syslogReporter = new SyslogReporter();
const reporter = new CompositeReporter([alertPrinter, fileLogger, syslogReporter]);
```

---

## 4. Writing Integration Tests

Every new channel, source, or validation rule must be accompanied by an integration test to protect against regressions:

1. Open `test-server/app.js` and add an endpoint that triggers the target code (e.g. a `/leak-file` endpoint).
2. Open `test-server/test/integration.test.js`.
3. Write a test case that makes an HTTP fetch request to the new endpoint, verifying that:
   - The leak is caught and printed by envtrap.
   - The generated `.envtrap-report.json` contains the leak under the correct channel name.
   - In block mode, the process is terminated and the fetch request fails/returns a 502 error.
