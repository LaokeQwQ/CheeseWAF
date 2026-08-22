export const accountStorageKey = 'cheesewaf-account';

export type AccountProfile = {
  subject: string;
  username: string;
  role: string;
  scopes: string[];
};

type AccountInput = Partial<AccountProfile> & { id?: string };

function emptyAccount(): AccountProfile {
  return { subject: '', username: '', role: '', scopes: [] };
}

function normalizeScopes(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return [...new Set(value
    .filter((scope): scope is string => typeof scope === 'string')
    .map((scope) => scope.trim())
    .filter(Boolean))];
}

export function cacheAccount(input: AccountInput | null | undefined) {
  if (!input) {
    return;
  }
  const account: AccountProfile = {
    subject: String(input.subject ?? input.id ?? '').trim(),
    username: String(input.username ?? '').trim(),
    role: String(input.role ?? '').trim(),
    scopes: normalizeScopes(input.scopes),
  };
  try {
    sessionStorage.setItem(accountStorageKey, JSON.stringify(account));
  } catch {
    // The session still works when browser storage is unavailable.
  }
}

export function currentAccount(): AccountProfile {
  try {
    const cached = sessionStorage.getItem(accountStorageKey);
    if (!cached) {
      return emptyAccount();
    }
    const parsed = JSON.parse(cached) as AccountInput;
    return {
      subject: String(parsed.subject ?? parsed.id ?? '').trim(),
      username: String(parsed.username ?? '').trim(),
      role: String(parsed.role ?? '').trim(),
      scopes: normalizeScopes(parsed.scopes),
    };
  } catch {
    return emptyAccount();
  }
}

export function clearAccount() {
  try {
    sessionStorage.removeItem(accountStorageKey);
  } catch {
    // The session still works when browser storage is unavailable.
  }
}

export function hasScope(account: AccountProfile, requiredScope: string): boolean {
  const required = requiredScope.trim();
  if (!required) {
    return false;
  }
  if (account.role === 'admin') {
    return true;
  }
  const scopes = account.scopes.length > 0
    ? account.scopes
    : account.role === 'readonly'
      ? ['read:*', 'read:cluster']
      : [];
  return scopes.some((scope) => scope === '*' || scope === required || (scope.endsWith('*') && required.startsWith(scope.slice(0, -1))));
}

export function filterNavigation<G extends { items: readonly { requiredScopes: string[] }[] }>(groups: readonly G[], account: AccountProfile): Array<Omit<G, 'items'> & { items: Array<G['items'][number]> }> {
  return groups
    .map((group) => ({ ...group, items: group.items.filter((item) => item.requiredScopes.some((scope) => hasScope(account, scope))) }))
    .filter((group) => group.items.length > 0);
}
