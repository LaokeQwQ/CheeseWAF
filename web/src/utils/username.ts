export const USERNAME_MIN = 3;
export const USERNAME_MAX = 32;

export type UsernameErrorCode =
  | 'required'
  | 'whitespace'
  | 'tooShort'
  | 'tooLong'
  | 'mustStartWithLetter'
  | 'invalidChars'
  | 'mustEndAlnum';

type UsernameNamespace = 'setup' | 'users' | 'login';

const USERNAME_ERROR_KEYS: Record<UsernameNamespace, Record<UsernameErrorCode, string>> = {
  setup: {
    required: 'setup.usernameRequired',
    whitespace: 'setup.usernameWhitespace',
    tooShort: 'setup.usernameTooShort',
    tooLong: 'setup.usernameTooLong',
    mustStartWithLetter: 'setup.usernameMustStartWithLetter',
    invalidChars: 'setup.usernameInvalidChars',
    mustEndAlnum: 'setup.usernameMustEndAlnum',
  },
  users: {
    required: 'users.usernameRequired',
    whitespace: 'users.usernameWhitespace',
    tooShort: 'users.usernameTooShort',
    tooLong: 'users.usernameTooLong',
    mustStartWithLetter: 'users.usernameMustStartWithLetter',
    invalidChars: 'users.usernameInvalidChars',
    mustEndAlnum: 'users.usernameMustEndAlnum',
  },
  login: {
    required: 'login.usernameRequired',
    whitespace: 'login.usernameWhitespace',
    tooShort: 'login.usernameInvalid',
    tooLong: 'login.usernameInvalid',
    mustStartWithLetter: 'login.usernameInvalid',
    invalidChars: 'login.usernameInvalid',
    mustEndAlnum: 'login.usernameInvalid',
  },
};

// `\p{Cf}` covers format/invisible characters such as U+200B ZERO WIDTH SPACE;
// `\p{Cc}` covers C0/C1 controls, and `\p{White_Space}` covers Unicode spaces.
const USERNAME_WHITESPACE_OR_INVISIBLE = /[\p{White_Space}\p{Cc}\p{Cf}]/u;
const USERNAME_ALLOWED = /^[A-Za-z][A-Za-z0-9._-]*$/;

/** Returns the canonical validation reason without changing the input. */
export function usernameValidationError(raw: string): UsernameErrorCode | null {
  if (!raw) return 'required';
  if (USERNAME_WHITESPACE_OR_INVISIBLE.test(raw)) return 'whitespace';

  const length = [...raw].length;
  if (length < USERNAME_MIN) return 'tooShort';
  if (length > USERNAME_MAX) return 'tooLong';
  if (!/^[A-Za-z]/.test(raw)) return 'mustStartWithLetter';
  if (!/[A-Za-z0-9]$/.test(raw)) return 'mustEndAlnum';
  if (!USERNAME_ALLOWED.test(raw)) return 'invalidChars';
  return null;
}

/** Returns an i18n key for a canonical account name, or null. */
export function usernameErrorKey(raw: string, namespace: UsernameNamespace = 'setup'): string | null {
  const code = usernameValidationError(raw);
  return code ? USERNAME_ERROR_KEYS[namespace][code] : null;
}

export function isCanonicalUsername(value: string): boolean {
  return usernameValidationError(value) === null;
}
