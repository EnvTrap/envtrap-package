// src/domain/ContentClamp.ts
// Clamps a string to a maximum byte size before scanning.
// Single responsibility: protect the V8 event loop from arbitrarily
// large buffers passed to the scanner.

const DEFAULT_MAX_BYTES = 1_048_576; // 1 MB

export class ContentClamp {
  constructor(private readonly maxBytes: number = DEFAULT_MAX_BYTES) {}

  /** Returns content clamped to maxBytes. No-op if already within limit. */
  clamp(content: string): string {
    if (content.length <= this.maxBytes) return content;
    return content.slice(0, this.maxBytes);
  }
}
