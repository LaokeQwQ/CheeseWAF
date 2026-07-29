/** Mirrors internal/passpolicy: ≥10 chars, ≥3 of 4 classes, reject weak patterns. */

export type PasswordClassFlags = {
  upper: boolean;
  lower: boolean;
  nonRepeatingDigit: boolean;
  special: boolean;
};

const MIN_LENGTH = 10;
const MIN_CLASSES = 3;

const WEAK_EXACT = new Set([
  'admin123456',
  'admin12345',
  'admin1234',
  'password',
  'password1',
  'password123',
  'passw0rd',
  '1234567890',
  '0123456789',
  'qwerty123',
  'letmein',
  'welcome1',
  'changeme',
  'cheesewaf',
  'root123456',
  'administrator',
]);

const WEAK_CONTAINS = ['admin123456', 'password123', 'qwertyui', 'iloveyou'];

export function classifyPassword(password: string): PasswordClassFlags {
  let upper = false;
  let lower = false;
  let special = false;
  const digitCounts = new Map<string, number>();
  const digitRun: string[] = [];

  for (const ch of password) {
    if (ch >= 'A' && ch <= 'Z') upper = true;
    else if (ch >= 'a' && ch <= 'z') lower = true;
    else if (ch >= '0' && ch <= '9') {
      digitCounts.set(ch, (digitCounts.get(ch) ?? 0) + 1);
      digitRun.push(ch);
    } else if (ch.trim() !== '') {
      special = true;
    }
  }

  let nonRepeatingDigit = false;
  if (digitCounts.size > 0) {
    const unique = [...digitCounts.values()].every((n) => n === 1);
    if (unique && !hasSequentialDigitRun(digitRun, 4)) {
      nonRepeatingDigit = true;
    }
  }

  return { upper, lower, nonRepeatingDigit, special };
}

export function passwordClassCount(flags: PasswordClassFlags): number {
  return [flags.upper, flags.lower, flags.nonRepeatingDigit, flags.special].filter(Boolean).length;
}

/** Returns i18n key suffix under passwordPolicy.* or null if valid. */
export function passwordPolicyErrorKey(password: string, username = ''): string | null {
  if ([...password].length < MIN_LENGTH) return 'tooShort';
  const uname = username.trim().toLowerCase();
  if (uname.length >= 3) {
    const p = password.toLowerCase();
    if (p === uname || p.includes(uname)) return 'usernameRelated';
  }
  if (isWeakPassword(password)) return 'weak';
  if (passwordClassCount(classifyPassword(password)) < MIN_CLASSES) return 'needClasses';
  return null;
}

function isWeakPassword(password: string): boolean {
  const lower = password.toLowerCase();
  const compact = lower.replace(/[^a-z0-9]/g, '');
  if (WEAK_EXACT.has(lower) || WEAK_EXACT.has(compact)) return true;
  for (const bad of WEAK_CONTAINS) {
    if (lower.includes(bad) || compact.includes(bad)) return true;
  }
  if (hasSequentialDigitRun(digitsOnly(password), 5)) return true;
  if (hasKeyboardSequence(compact, 6)) return true;
  if (password.length > 0 && [...password].every((c) => c === password[0])) return true;
  return false;
}

function digitsOnly(password: string): string[] {
  return [...password].filter((c) => c >= '0' && c <= '9');
}

function hasSequentialDigitRun(digits: string[], minLen: number): boolean {
  if (digits.length < minLen) return false;
  let asc = 1;
  let desc = 1;
  for (let i = 1; i < digits.length; i++) {
    const d0 = digits[i - 1].charCodeAt(0) - 48;
    const d1 = digits[i].charCodeAt(0) - 48;
    if (d1 === d0 + 1) {
      asc++;
      desc = 1;
    } else if (d1 === d0 - 1) {
      desc++;
      asc = 1;
    } else {
      asc = 1;
      desc = 1;
    }
    if (asc >= minLen || desc >= minLen) return true;
  }
  return false;
}

function hasKeyboardSequence(compact: string, minLen: number): boolean {
  if (compact.length < minLen) return false;
  const rows = [
    '01234567890',
    'qwertyuiop',
    'asdfghjkl',
    'zxcvbnm',
    'abcdefghijklmnopqrstuvwxyz',
  ];
  for (const row of rows) {
    const rev = [...row].reverse().join('');
    for (let i = 0; i + minLen <= row.length; i++) {
      const slice = row.slice(i, i + minLen);
      const rslice = rev.slice(i, i + minLen);
      if (compact.includes(slice) || compact.includes(rslice)) return true;
    }
  }
  return false;
}
