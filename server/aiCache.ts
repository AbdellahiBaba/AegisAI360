import crypto from "crypto";

interface CacheEntry {
  response: string;
  timestamp: number;
}

const cache = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 30 * 60 * 1000;
const MAX_CACHE_SIZE = 500;

export function aiCacheKey(...parts: string[]): string {
  return crypto.createHash("sha256").update(parts.join("|")).digest("hex");
}

export function getCached(key: string): string | null {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
    cache.delete(key);
    return null;
  }
  return entry.response;
}

export function setCache(key: string, response: string): void {
  if (response.length < 5) return;
  if (cache.size >= MAX_CACHE_SIZE) {
    const oldest = cache.keys().next().value;
    if (oldest) cache.delete(oldest);
  }
  cache.set(key, { response, timestamp: Date.now() });
}

export function compressChatHistory(
  messages: { role: string; content: string }[],
  maxMessages: number = 10,
  maxCharsPerAssistant: number = 1500,
): { role: string; content: string }[] {
  if (messages.length <= maxMessages) {
    return messages.map(m => ({
      ...m,
      content: m.role === "assistant" && m.content.length > maxCharsPerAssistant
        ? m.content.substring(0, maxCharsPerAssistant) + "\n[...truncated]"
        : m.content,
    }));
  }
  const first = messages[0];
  const recent = messages.slice(-(maxMessages - 1));
  return [first, ...recent].map(m => ({
    ...m,
    content: m.role === "assistant" && m.content.length > maxCharsPerAssistant
      ? m.content.substring(0, maxCharsPerAssistant) + "\n[...truncated]"
      : m.content,
  }));
}
