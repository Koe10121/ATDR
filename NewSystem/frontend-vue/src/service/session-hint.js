const SESSION_HINT_KEY = 'iam-session-hint-v1';

function getStorage() {
  if (typeof window === 'undefined' || !window.localStorage) {
    return null;
  }
  return window.localStorage;
}

export function hasSessionHint() {
  const storage = getStorage();
  if (!storage) return false;
  return storage.getItem(SESSION_HINT_KEY) === '1';
}

export function setSessionHint(enabled) {
  const storage = getStorage();
  if (!storage) return;
  if (enabled) {
    storage.setItem(SESSION_HINT_KEY, '1');
  } else {
    storage.removeItem(SESSION_HINT_KEY);
  }
}
