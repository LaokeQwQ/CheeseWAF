export type RuleTemplate = {
  key: string;
  label: string;
  pattern: string;
  description: string;
};

export function ruleTemplates(t: (key: string, options?: Record<string, unknown>) => string): RuleTemplate[] {
  return [
    { key: 'path-admin', label: t('rules.templatePathPrefix'), pattern: '^/admin(?:/|$)', description: t('rules.templatePathPrefixHint') },
    { key: 'path-api', label: t('rules.templateAPIPath'), pattern: '^/api/(?:v[12]/)?(?:users|admin|config|internal)', description: t('rules.templateAPIPathHint') },
    { key: 'path-backup', label: t('rules.templateBackupPath'), pattern: '\\.(?:bak|backup|old|tmp|swp|sql|zip|tar\\.gz|7z)$', description: t('rules.templateBackupPathHint') },
    { key: 'sql-union', label: t('rules.templateSQLi'), pattern: '(?i)(?:union\\s+select|select\\s+.+\\s+from|sleep\\s*\\(|waitfor\\s+delay|benchmark\\s*\\()', description: t('rules.templateSQLiHint') },
    { key: 'xss-script', label: t('rules.templateXSS'), pattern: '(?i)(?:<\\s*script|javascript:|on\\w+\\s*=|srcset\\s*=|formaction\\s*=)', description: t('rules.templateXSSHint') },
    { key: 'lfi', label: t('rules.templateLFI'), pattern: '(?i)(?:\\.\\./|\\.\\.\\\\|/etc/(?:passwd|shadow|hosts)|boot\\.ini|win\\.ini|proc/self)', description: t('rules.templateLFIHint') },
    { key: 'rce', label: t('rules.templateRCE'), pattern: '(?i)(?:;|\\|\\||&&|\\$\\()\\s*(?:cat|curl|wget|bash|sh|powershell|cmd|python|perl|php)\\b', description: t('rules.templateRCEHint') },
    { key: 'ssrf-internal', label: t('rules.templateSSRF'), pattern: '(?i)(?:https?|gopher|dict|ftp)://(?:localhost|127\\.|10\\.|172\\.1[6-9]|172\\.2\\d|172\\.3[0-1]|192\\.168\\.|169\\.254)', description: t('rules.templateSSRFHint') },
    { key: 'json-field', label: t('rules.templateJSONField'), pattern: '"(?:role|is_admin|permission|admin|root)"\\s*:\\s*(?:true|1|null)', description: t('rules.templateJSONFieldHint') },
    { key: 'header-auth', label: t('rules.templateAuthHeader'), pattern: '^(?:Bearer\\s+(?:ey|invalid)|Basic\\s+(?:test|admin):|Authorization:\\s*$)', description: t('rules.templateAuthHeaderHint') },
    { key: 'ua-bot', label: t('rules.templateBotUA'), pattern: '(?i)(?:sqlmap|nikto|nuclei|masscan|zgrab|dirbuster|burp|nessus)', description: t('rules.templateBotUAHint') },
    { key: 'ssti', label: t('rules.templateSSTI'), pattern: '(?i)(?:\\{\\{.*?\\}\\}|\\$\\{.*?\\}|<%=.*?%>|__class__|__globals__|__import__)', description: t('rules.templateSSTIHint') },
  ];
}

export function testPattern(pattern: string, input: string): { ok: true; matched: boolean } | { ok: false; error: string } {
  if (!pattern.trim() || !input.trim()) {
    return { ok: true, matched: false };
  }
  try {
    return { ok: true, matched: compileRulePattern(pattern).test(input) };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : 'Invalid expression' };
  }
}

export function validateRuleDraft(
  pattern: string,
  priority: number,
  t: (key: string, options?: Record<string, unknown>) => string,
): { ok: true } | { ok: false; error: string } {
  if (!pattern.trim()) {
    return { ok: false, error: t('rules.patternRequired') };
  }
  if (!Number.isFinite(priority) || priority < 1 || priority > 999) {
    return { ok: false, error: t('rules.priorityInvalid') };
  }
  try {
    compileRulePattern(pattern);
  } catch (error) {
    const message = error instanceof Error ? error.message : t('rules.patternInvalid');
    return { ok: false, error: t('rules.patternInvalidWithReason', { reason: message }) };
  }
  if (isDangerouslyBroadPattern(pattern)) {
    return { ok: false, error: t('rules.patternTooBroad') };
  }
  return { ok: true };
}

export function compileRulePattern(pattern: string) {
  const trimmed = pattern.trim();
  const inlineFlags = /^\(\?([imsu]+)\)/i.exec(trimmed);
  if (!inlineFlags) {
    return new RegExp(trimmed);
  }
  const flags = Array.from(new Set(inlineFlags[1].toLowerCase().split(''))).join('');
  return new RegExp(trimmed.slice(inlineFlags[0].length), flags);
}

export function isDangerouslyBroadPattern(pattern: string) {
  const normalized = pattern
    .trim()
    .replace(/^\(\?[imsu]+\)/i, '')
    .replace(/\s+/g, '');
  return normalized === '' || ['.*', '.+', '^.*$', '^.+$', '.*?', '^.*?$', '[\\s\\S]*', '^[\\s\\S]*$'].includes(normalized);
}
