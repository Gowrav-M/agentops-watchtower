import type { JsonValue } from "./schemas.js";

const SENSITIVE_KEY_PATTERN =
  /(?:api[_-]?key|token|secret|password|passwd|credential|authorization|private[_-]?key|mfa|otp|session[_-]?id)/i;

export function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY_PATTERN.test(key);
}

export function redactSecrets<T extends JsonValue>(value: T): T {
  return redactJson(value) as T;
}

function redactJson(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    return value.map((item) => redactJson(item));
  }

  if (value !== null && typeof value === "object") {
    const redacted: Record<string, JsonValue> = {};
    for (const [key, child] of Object.entries(value)) {
      redacted[key] = isSensitiveKey(key) ? "[REDACTED]" : redactJson(child);
    }
    return redacted;
  }

  return value;
}
