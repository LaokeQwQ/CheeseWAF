import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import zhCN from './locales/zh-CN';
import type { Language } from '../stores';

/**
 * Only the default locale (zh-CN) ships in the entry chunk. Every other locale
 * is fetched on demand so the initial bundle does not carry ~198KB of
 * translations for two languages at once.
 *
 * `ensureLanguage` must be awaited before `changeLanguage`, otherwise i18next
 * renders raw keys for a locale whose resources have not arrived yet.
 */
const loaders: Record<Exclude<Language, 'zh-CN'>, () => Promise<{ default: unknown }>> = {
  'en-US': () => import('./locales/en-US'),
};

const ready = new Set<Language>(['zh-CN']);

/** Returns the language the operator explicitly picked, or null when unset. */
export function readPersistedLanguage(): Language | null {
  try {
    const persisted = JSON.parse(localStorage.getItem('cheesewaf-ui') ?? '{}') as {
      state?: { language?: unknown };
    };
    const language = persisted.state?.language;
    if (language === 'zh-CN' || language === 'en-US') {
      return language;
    }
  } catch {
    // Invalid local preferences must not prevent the console from loading.
  }
  return null;
}

export function readInitialLanguage(): Language {
  return readPersistedLanguage() ?? 'zh-CN';
}

/** Resolves once the resources for `language` are available. */
export async function ensureLanguage(language: Language): Promise<void> {
  if (ready.has(language)) {
    return;
  }
  const load = loaders[language as Exclude<Language, 'zh-CN'>];
  if (!load) {
    return;
  }
  const module = await load();
  i18n.addResourceBundle(language, 'translation', module.default, true, true);
  ready.add(language);
}

i18n.use(initReactI18next).init({
  resources: {
    'zh-CN': { translation: zhCN },
  },
  lng: readInitialLanguage(),
  fallbackLng: 'zh-CN',
  interpolation: {
    escapeValue: false,
  },
});

export default i18n;
