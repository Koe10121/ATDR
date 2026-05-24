import { useEffect, useState } from "react";

export function usePersistentState<T>(key: string, initialValue: T): [T, (next: T | ((current: T) => T)) => void] {
  const [value, setValue] = useState<T>(() => {
    const raw = window.localStorage.getItem(key);
    if (!raw) return initialValue;
    try {
      const parsed = JSON.parse(raw) as T;
      if (Array.isArray(initialValue)) {
        return (Array.isArray(parsed) ? parsed : initialValue) as T;
      }
      if (
        typeof initialValue === "object" &&
        initialValue !== null &&
        !Array.isArray(initialValue) &&
        typeof parsed === "object" &&
        parsed !== null &&
        !Array.isArray(parsed)
      ) {
        return { ...initialValue, ...parsed } as T;
      }
      if (parsed === null || typeof parsed !== typeof initialValue) {
        return initialValue;
      }
      return parsed;
    } catch {
      return initialValue;
    }
  });

  useEffect(() => {
    window.localStorage.setItem(key, JSON.stringify(value));
  }, [key, value]);

  return [value, setValue];
}
