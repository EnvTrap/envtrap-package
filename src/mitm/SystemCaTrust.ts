// src/mitm/SystemCaTrust.ts
// OS-level certificate trust-store management.
//
// Separated from CertificateAuthority.ts so the crypto module has no OS
// dependencies and can be tested on any platform without mocking system calls.

import * as fs from 'fs';
import { execFileSync } from 'child_process';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isRoot(): boolean {
  try {
    return process.getuid !== undefined && process.getuid() === 0;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Installs the Root CA certificate into the OS system trust store.
 * Skipped gracefully (with optional log) when not running as root/admin.
 *
 * Platform support:
 *   - macOS:  security add-trusted-cert
 *   - Windows: certutil -addstore (no UAC elevation needed for -user store)
 *   - Debian/Ubuntu Linux: update-ca-certificates
 *   - RHEL/Fedora/CentOS Linux: update-ca-trust
 */
export function injectSystemCA(caCertPath: string, verbose = false): void {
  const platform = process.platform;

  if (!isRoot() && platform !== 'win32') {
    if (verbose) {
      console.error(
        '[envtrap] info: Cross-language CA injection skipped (requires root/sudo)',
      );
    }
    return;
  }

  try {
    if (platform === 'darwin') {
      execFileSync(
        'security',
        ['add-trusted-cert', '-d', '-r', 'trustRoot', '-k', '/Library/Keychains/System.keychain', caCertPath],
        { stdio: 'ignore' },
      );
      if (verbose) console.error('[envtrap] info: CA added to macOS Keychain');

    } else if (platform === 'win32') {
      execFileSync('certutil', ['-addstore', '-user', 'root', caCertPath], { stdio: 'ignore' });
      if (verbose) console.error('[envtrap] info: CA added to Windows Trusted Root');

    } else if (platform === 'linux') {
      if (fs.existsSync('/usr/local/share/ca-certificates/')) {
        fs.copyFileSync(caCertPath, '/usr/local/share/ca-certificates/envtrap-ca.crt');
        execFileSync('update-ca-certificates', [], { stdio: 'ignore' });
        if (verbose) console.error('[envtrap] info: CA added to Debian/Ubuntu trust store');
      } else if (fs.existsSync('/etc/pki/ca-trust/source/anchors/')) {
        fs.copyFileSync(caCertPath, '/etc/pki/ca-trust/source/anchors/envtrap-ca.crt');
        execFileSync('update-ca-trust', [], { stdio: 'ignore' });
        if (verbose) console.error('[envtrap] info: CA added to RHEL/Fedora trust store');
      }
    }
  } catch (err) {
    if (verbose) {
      console.error(
        `[envtrap] warning: Failed to install CA to system trust store: ${(err as Error).message}`,
      );
    }
  }
}

/**
 * Removes the Root CA certificate from the OS system trust store.
 * Called at child process exit to clean up the temporary installation.
 * Always fails silently — cleanup must never crash the process.
 */
export function removeSystemCA(caCertPath: string): void {
  if (!isRoot() && process.platform !== 'win32') return;

  try {
    const platform = process.platform;

    if (platform === 'darwin') {
      execFileSync('security', ['remove-trusted-cert', '-d', caCertPath], { stdio: 'ignore' });

    } else if (platform === 'win32') {
      execFileSync('certutil', ['-delstore', '-user', 'root', 'envtrap Root CA'], { stdio: 'ignore' });

    } else if (platform === 'linux') {
      if (fs.existsSync('/usr/local/share/ca-certificates/envtrap-ca.crt')) {
        fs.unlinkSync('/usr/local/share/ca-certificates/envtrap-ca.crt');
        execFileSync('update-ca-certificates', ['--fresh'], { stdio: 'ignore' });
      } else if (fs.existsSync('/etc/pki/ca-trust/source/anchors/envtrap-ca.crt')) {
        fs.unlinkSync('/etc/pki/ca-trust/source/anchors/envtrap-ca.crt');
        execFileSync('update-ca-trust', [], { stdio: 'ignore' });
      }
    }
  } catch {
    // Graceful fail-open on cleanup — never crash at exit
  }
}
