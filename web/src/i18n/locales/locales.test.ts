import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import enUS from './en-US';
import zhCN from './zh-CN';

const webSrcDir = resolve(process.cwd(), 'src');

function leafKeys(value: unknown, prefix = ''): string[] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return [prefix];
  return Object.entries(value as Record<string, unknown>)
    .flatMap(([key, child]) => leafKeys(child, prefix ? `${prefix}.${key}` : key))
    .sort();
}

/** Prefixes used via dynamic t(`prefix.${var}`) — never treat as dead. */
const DYNAMIC_PREFIXES = [
  'geo.countries.',
  'geo.continents.',
  'login.captchaState.',
  'protection.captchaTypes.',
  'protection.policyLevels.',
  'blockPages.templateNames.',
  'blockPages.templateDescriptions.',
  'securityActions.',
  'securityCategories.',
  'securitySeverity.',
  'botChallenge.captchaAssets.kinds.',
  'botChallenge.outcomes.',
  'botChallenge.ranges.',
  'sites.acmeStep.',
  'shell.notification',
  'passwordPolicy.',
  'ai.toolNames.',
  'ai.toolDescriptions.',
  'assistant.toolNames.',
  'assistant.toolDescriptions.',
  'assistant.approvalStatus.',
  'assistant.sensitivity.',
  'attackMap.precisionLevel.',
  'captchaLab.status.',
  'captchaLab.types.',
];

/** Remaining dead keys left intentionally (ambiguous leaf or deferred cleanup). */
const DEAD_KEY_ALLOWLIST = new Set([
  // shared leaf names across namespaces — deferred structural cleanup
  'system.acme',
  'system.disable2FA',
  'system.disable2FAConfirm',
  'system.disable2FAConfirmTitle',
  'system.enable2FA',
  'system.setup2FA',
  'system.timeout',
  'system.twoFA',
  'system.twoFADisabled',
  'system.twoFAEnabled',
  'system.twoFAGuide',
  'system.updates',
  'system.verify2FA',
  'system.vulnerabilityFeeds',
  'system.performance',
  'assistant.streamingAnswer',
  'assistant.seed',
  'assistant.approval',
  'protection.botChallenge',
  'attackMap.continent',
  'attackMap.timeRange',
  'blockPages.editor',
  'botChallenge.loading',
  'common.blocked',
  'common.log',
  'common.zoomIn',
  'common.zoomOut',
  'logs.pass',
  'ops.history',
  'rules.scope',
  'rules.title',
  'sites.acmeCertDir',
  'sites.acmeHome',
  'sites.acmePath',
  'sites.acmeReloadCommand',
  'updates.ota',
  'users.disable2FAConfirm',
  'users.disable2FAConfirmTitle',
  'ai.result',
  'dashboard.refresh',
  'dashboard.traffic',
  'dashboard.swapNotEnabled',
  'shell.attacks',
  'shell.latency',
  'shell.requests',
  'assistant.analysisTrace',
  'assistant.liveReasoning',
]);

const REQUIRED_KEYS = [
  'attackMap.basemapCredit3d',
  'attackMap.basemapCreditChina',
  'attackMap.basemapCreditWorld',
  'ops.shareHint',
  'ops.defaultDailyReport',
  'ops.defaultSecurityReport',
  'ops.defaultLogCleanup',
  'system.acmeEnvKeyDuplicate',
  'geo.continents.middleEast',
  'ip.defaultAccessRuleName',
  'passwordPolicy.tooShort',
  'passwordPolicy.needClasses',
  'passwordPolicy.weak',
  'passwordPolicy.usernameRelated',
  'common.loadFailed',
  'common.home',
];

function collectSourceFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) {
      if (name === 'locales' && full.replace(/\\/g, '/').endsWith('i18n/locales')) continue;
      if (name === 'node_modules' || name === 'dist') continue;
      collectSourceFiles(full, out);
      continue;
    }
    if (/\.(ts|tsx)$/.test(name) && !full.includes(`${join('i18n', 'locales')}`)) {
      out.push(full);
    }
  }
  return out;
}

function keyReferenced(key: string, blobs: string[]): boolean {
  if (DYNAMIC_PREFIXES.some((prefix) => key.startsWith(prefix) || prefix.startsWith(`${key}.`))) {
    return true;
  }
  const patterns = [`'${key}'`, `"${key}"`, `\`${key}\``];
  return blobs.some((blob) => patterns.some((p) => blob.includes(p)));
}

describe('locale dictionaries', () => {
  it('keep English and Simplified Chinese key sets identical', () => {
    expect(leafKeys(zhCN)).toEqual(leafKeys(enUS));
  });

  it('do not contain blank user-facing strings', () => {
    for (const locale of [enUS, zhCN]) {
      const blanks = leafKeys(locale).filter((key) => {
        const value = key.split('.').reduce<unknown>((current, part) => (
          current && typeof current === 'object' ? (current as Record<string, unknown>)[part] : undefined
        ), locale);
        return typeof value === 'string' && value.trim() === '';
      });
      expect(blanks).toEqual([]);
    }
  });

  it('includes keys required by admin UI (kimi_i18n problem 1 + password policy)', () => {
    const keys = new Set(leafKeys(enUS));
    for (const key of REQUIRED_KEYS) {
      expect(keys.has(key), `missing required key ${key}`).toBe(true);
    }
  });

  it('does not accumulate new unreferenced keys outside the allowlist', () => {
    const files = collectSourceFiles(webSrcDir);
    const blobs = files.map((file) => readFileSync(file, 'utf8'));
    const unreferenced = leafKeys(enUS).filter((key) => {
      if (DYNAMIC_PREFIXES.some((prefix) => key.startsWith(prefix))) return false;
      if (DEAD_KEY_ALLOWLIST.has(key)) return false;
      return !keyReferenced(key, blobs);
    });
    expect(unreferenced, `new dead keys:\n${unreferenced.join('\n')}`).toEqual([]);
  });
});
