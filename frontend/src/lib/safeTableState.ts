export interface NamedSavedView<T> {
  name: string;
  value: T;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function normalizeStringState<T extends Record<string, string>>(
  defaults: T,
  value: unknown,
  constraints: Partial<Record<keyof T, readonly string[]>> = {}
): T {
  const source = isRecord(value) ? value : {};
  const normalized = { ...defaults };
  (Object.keys(defaults) as Array<keyof T>).forEach((key) => {
    const raw = source[String(key)];
    const next = typeof raw === "string" ? raw : defaults[key];
    const allowedValues = constraints[key];
    normalized[key] = (allowedValues && !allowedValues.includes(next) ? defaults[key] : next) as T[keyof T];
  });
  return normalized;
}

export function normalizeSavedViews<T>(value: unknown, normalizeValue: (raw: unknown) => T): Array<NamedSavedView<T>> {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .filter((item): item is Record<string, unknown> => isRecord(item) && typeof item.name === "string" && item.name.trim().length > 0)
    .map((item) => ({ name: String(item.name).trim(), value: normalizeValue(item.value) }));
}
