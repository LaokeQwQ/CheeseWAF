type Translator = (key: string, options?: Record<string, unknown>) => string;

const categoryKeys: Record<string, string> = {
  acl: 'securityCategories.acl',
  bot: 'securityCategories.bot',
  challenge: 'securityActions.challenge',
  custom_rule: 'securityCategories.customRule',
  geoip: 'securityCategories.geoip',
  lfi: 'securityCategories.lfi',
  nosqli: 'securityCategories.nosqli',
  pass: 'securityActions.pass',
  ratelimit: 'securityCategories.ratelimit',
  rce: 'securityCategories.rce',
  response: 'securityCategories.response',
  semantic: 'securityCategories.semantic',
  sqli: 'securityCategories.sqli',
  ssrf: 'securityCategories.ssrf',
  ssti: 'securityCategories.ssti',
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
  AE: 'geo.countries.AE',
  AR: 'geo.countries.AR',
  AT: 'geo.countries.AT',
  AU: 'geo.countries.AU',
  BE: 'geo.countries.BE',
  BG: 'geo.countries.BG',
  BR: 'geo.countries.BR',
  CA: 'geo.countries.CA',
  CH: 'geo.countries.CH',
  CL: 'geo.countries.CL',
  CN: 'geo.countries.CN',
  CO: 'geo.countries.CO',
  CZ: 'geo.countries.CZ',
  DE: 'geo.countries.DE',
  DK: 'geo.countries.DK',
  EG: 'geo.countries.EG',
  ES: 'geo.countries.ES',
  FI: 'geo.countries.FI',
  FR: 'geo.countries.FR',
  GB: 'geo.countries.GB',
  GR: 'geo.countries.GR',
  HK: 'geo.countries.HK',
  HU: 'geo.countries.HU',
  ID: 'geo.countries.ID',
  IE: 'geo.countries.IE',
  IL: 'geo.countries.IL',
  IN: 'geo.countries.IN',
  IR: 'geo.countries.IR',
  IT: 'geo.countries.IT',
  JP: 'geo.countries.JP',
  KE: 'geo.countries.KE',
  KZ: 'geo.countries.KZ',
  KR: 'geo.countries.KR',
  MA: 'geo.countries.MA',
  MX: 'geo.countries.MX',
  LOCAL: 'geo.local',
  MY: 'geo.countries.MY',
  NG: 'geo.countries.NG',
  NL: 'geo.countries.NL',
  NO: 'geo.countries.NO',
  NZ: 'geo.countries.NZ',
  PE: 'geo.countries.PE',
  PH: 'geo.countries.PH',
  PK: 'geo.countries.PK',
  PL: 'geo.countries.PL',
  PT: 'geo.countries.PT',
  RO: 'geo.countries.RO',
  RU: 'geo.countries.RU',
  SA: 'geo.countries.SA',
  SE: 'geo.countries.SE',
  SG: 'geo.countries.SG',
  SI: 'geo.countries.SI',
  SK: 'geo.countries.SK',
  TH: 'geo.countries.TH',
  TR: 'geo.countries.TR',
  TW: 'geo.countries.TW',
  UA: 'geo.countries.UA',
  UNLOCATED: 'geo.unlocated',
  US: 'geo.countries.US',
  VE: 'geo.countries.VE',
  VN: 'geo.countries.VN',
  ZA: 'geo.countries.ZA',
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
