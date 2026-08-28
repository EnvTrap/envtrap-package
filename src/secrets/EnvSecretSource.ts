// src/secrets/EnvSecretSource.ts
// Loads secret candidates from process.env.
// Single responsibility: one source, one medium.

import { looksLikeSecret } from '../detection/fingerprint.js';
import type { ISecretSource } from '../ports/ISecretSource.js';
import type { Secret } from '../types.js';
import type { EntropyConfig } from '../config/ConfigTypes.js';

// Variables that are never secret values — system/tooling env vars.
const SYSTEM_BLOCKLIST = new Set([
  'PATH', 'HOME', 'USER', 'SHELL', 'PWD', 'LANG', 'TERM', 'SHLVL', 'LOGNAME',
  'MAIL', 'HOSTNAME', 'HISTCONTROL', 'LESSOPEN', 'LESSCLOSE', '_',
  'XDG_DATA_DIRS', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS',
  'DEBUGINFOD_URLS', 'NVM_DIR', 'NVM_BIN', 'NVM_INC', 'PNPM_HOME',
  'NODE_ENV', 'NODE_OPTIONS', 'QT_IM_MODULES', 'XMODIFIERS', 'GPG_TTY',
  'EDITOR', 'XAUTHORITY', 'GDM_LANG', 'WAYLAND_DISPLAY', 'INVOCATION_ID',
  'JOURNAL_STREAM', 'CHROME_DESKTOP', 'GJS_DEBUG_TOPICS', 'GNOME_SETUP_DISPLAY',
  'DISPLAY', 'OLDPWD', 'SSH_ASKPASS', 'SSH_AUTH_SOCK', 'LS_COLORS',
  'XDG_SESSION_PATH', 'XDG_SEAT_PATH', 'XDG_SESSION_ID', 'XDG_SESSION_TYPE',
  'XDG_SESSION_CLASS', 'XDG_SESSION_DESKTOP', 'XDG_CURRENT_DESKTOP',
  'GDMSESSION', 'DESKTOP_SESSION', 'XDG_CONFIG_DIRS', 'XDG_SEAT',
  'XDG_VTNR', 'QT_ACCESSIBILITY', 'QT_AUTO_SCREEN_SCALE_FACTOR',
  'GTK_IM_MODULE', 'GTK_MODULES', 'GNOME_JOURNAL_STREAM', 'DBUS_STARTER_BUS_TYPE',
  'DBUS_STARTER_ADDRESS', 'MANAGERPID', 'SYSTEMD_EXEC_PID', 'XDG_MENU_PREFIX',
  'MEMORY_PRESSURE_WATCH', 'MEMORY_PRESSURE_WRITE', 'XDG_SESSION_EXTRA_DEVICE_ACCESS',
  'ANTIGRAVITY_LS_ADDRESS', 'ANTIGRAVITY_CSRF_TOKEN', 'ANTIGRAVITY_SOURCE_METADATA',
  'ANTIGRAVITY_TRAJECTORY_ID', 'ANTIGRAVITY_PROJECT_ID', 'AGY_BROWSER_WS_URL',
  'AGY_BROWSER_ACTIVE_PORT_FILE', 'CHROME_DEVTOOLS_MCP_JS',
]);

export class EnvSecretSource implements ISecretSource {
  constructor(private readonly entropy: EntropyConfig) {}

  load(): Secret[] {
    return Object.entries(process.env)
      .filter(([name, value]) => this.isCandidate(name, value))
      .map(([name, value]) => ({ name, value: value as string, source: 'env' as const }));
  }

  private isCandidate(name: string, value: string | undefined): value is string {
    return (
      !SYSTEM_BLOCKLIST.has(name) &&
      value !== undefined &&
      looksLikeSecret(value, this.entropy.minLength, this.entropy.threshold)
    );
  }
}
