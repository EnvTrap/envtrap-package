// src/domain/DedupCache.ts
// TTL-based deduplication cache.
// Single responsibility: track whether a (name, channel) pair was
// recently seen and suppress duplicate events within the TTL window.

export class DedupCache {
  private readonly cache = new Map<string, number>();

  constructor(private readonly ttlMs: number = 1_500) {}

  /** Returns true if this key was seen within the TTL window. */
  isDuplicate(key: string): boolean {
    const lastSeen = this.cache.get(key);
    return lastSeen !== undefined && Date.now() - lastSeen < this.ttlMs;
  }

  /** Record a key as seen right now. */
  record(key: string): void {
    this.cache.set(key, Date.now());
  }
}
