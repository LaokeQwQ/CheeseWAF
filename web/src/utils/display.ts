type Translator = (key: string, options?: Record<string, unknown>) => string;

const categoryKeys: Record<string, string> = {
  acl: 'securityCategories.acl',
  bot: 'securityCategories.bot',
  challenge: 'securityActions.challenge',
  custom_rule: 'securityCategories.customRule',
  geoip: 'securityCategories.geoip',
  lfi: 'securityCategories.lfi',
  pass: 'securityActions.pass',
  ratelimit: 'securityCategories.ratelimit',
  rce: 'securityCategories.rce',
  response: 'securityCategories.response',
  semantic: 'securityCategories.semantic',
  sqli: 'securityCategories.sqli',
  ssrf: 'securityCategories.ssrf',
  threat_intel: 'securityCategories.threatIntel',
  unknown: 'securityCategories.unknown',
  xss: 'securityCategories.xss',
};

const severityKeys: Record<string, string> = {
  critical: 'rules.critical',
  high: 'rules.high',
  info: 'securitySeverity.info',
  low: 'rules.low',
  medium: 'rules.medium',
};

const actionKeys: Record<string, string> = {
  allow: 'securityActions.pass',
  block: 'common.block',
  challenge: 'securityActions.challenge',
  log: 'securityActions.log',
  monitor: 'common.monitor',
  pass: 'securityActions.pass',
};

const countryKeys: Record<string, string> = {
  AU: 'geo.countries.AU',
  BR: 'geo.countries.BR',
  CA: 'geo.countries.CA',
  CN: 'geo.countries.CN',
  DE: 'geo.countries.DE',
  FR: 'geo.countries.FR',
  GB: 'geo.countries.GB',
  HK: 'geo.countries.HK',
  ID: 'geo.countries.ID',
  IN: 'geo.countries.IN',
  JP: 'geo.countries.JP',
  KR: 'geo.countries.KR',
  LOCAL: 'geo.local',
  NL: 'geo.countries.NL',
  RU: 'geo.countries.RU',
  SG: 'geo.countries.SG',
  TH: 'geo.countries.TH',
  UNLOCATED: 'geo.unlocated',
  US: 'geo.countries.US',
  VN: 'geo.countries.VN',
};

const continentKeys: Record<string, string> = {
  Africa: 'geo.continents.africa',
  Antarctica: 'geo.continents.antarctica',
  Asia: 'geo.continents.asia',
  Europe: 'geo.continents.europe',
  'Europe/Asia': 'geo.continents.eurasia',
  LOCAL: 'geo.local',
  'North America': 'geo.continents.northAmerica',
  Oceania: 'geo.continents.oceania',
  'South America': 'geo.continents.southAmerica',
  UNLOCATED: 'geo.unlocated',
};

export function displayCategory(value: string | undefined, t: Translator) {
  const key = normalizeToken(value);
  return t(categoryKeys[key] ?? 'securityCategories.customRule');
}

export function displaySeverity(value: string | undefined, t: Translator) {
  const key = normalizeToken(value);
  return t(severityKeys[key] ?? 'securitySeverity.unknown');
}

export function displayAction(value: string | undefined, t: Translator) {
  const key = normalizeToken(value);
  return t(actionKeys[key] ?? 'common.monitor');
}

export function displayCountry(code: string | undefined, t: Translator) {
  const normalized = normalizeCountryCode(code);
  return t(countryKeys[normalized] ?? 'geo.unlocated');
}

export function displayContinent(continent: string | undefined, t: Translator) {
  return t(continentKeys[String(continent ?? '').trim()] ?? 'geo.unlocated');
}

export function normalizeCountryCode(value: string | undefined) {
  const raw = String(value ?? '').trim().toUpperCase();
  if (!raw || raw === 'UNKNOWN' || raw === 'UNLOCATED' || raw === '-') {
    return 'UNLOCATED';
  }
  if (raw === 'LOCAL' || raw === 'PRIVATE' || raw === 'LOOPBACK') {
    return 'LOCAL';
  }
  return raw;
}

function normalizeToken(value: string | undefined) {
  return String(value ?? '').trim().toLowerCase().replace(/[-\s]+/g, '_') || 'unknown';
}
