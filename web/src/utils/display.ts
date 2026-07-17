type Translator = (key: string, options?: Record<string, unknown>) => string;

const categoryKeys: Record<string, string> = {
  acl: 'securityCategories.acl',
  bot: 'securityCategories.bot',
  challenge: 'securityActions.challenge',
  custom_rule: 'securityCategories.customRule',
  detection_budget: 'securityCategories.detectionBudget',
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

export function displayGeoPlace(value: string | undefined, countryCode: string | undefined, t: Translator) {
  const raw = String(value ?? '').trim();
  if (!raw) {
    return '';
  }
  const normalizedCountry = normalizeCountryCode(countryCode);
  if (normalizedCountry === 'CN') {
    const key = normalizePlaceKey(raw);
    return cnPlaceNames[key] ?? raw;
  }
  return raw;
}

export function isSameGeoCountry(value: string | undefined, countryCode: string | undefined, t: Translator) {
  const raw = String(value ?? '').trim();
  if (!raw) {
    return false;
  }
  const normalized = normalizeCountryCode(countryCode);
  if (normalized === 'UNLOCATED') {
    return false;
  }
  const candidate = normalizeCountryCode(raw);
  if (candidate === normalized) {
    return true;
  }
  const localized = displayCountry(normalized, t);
  return normalizePlaceKey(raw) === normalizePlaceKey(localized);
}

export function formatLogLocation(
  entry: {
    country?: string;
    client_ip?: string;
    metadata?: Record<string, unknown>;
  },
  t: Translator,
) {
  const geo = metadataGeo(entry.metadata);
  const countryCode = normalizeCountryCode(stringValue(geo?.country_code) || stringValue(geo?.country) || stringValue(geo?.country_name) || entry.country);
  const countryName = displayGeoCountryName(countryCode, stringValue(geo?.country_name), t);
  const parts = [
    countryName,
    displayGeoPlace(stringValue(geo?.region), countryCode, t),
    displayGeoPlace(stringValue(geo?.city), countryCode, t),
    displayGeoPlace(stringValue(geo?.district), countryCode, t),
    displayGeoPlace(stringValue(geo?.street), countryCode, t),
  ].filter(Boolean);
  if (parts.length > 0) {
    return Array.from(new Set(parts)).join(' / ');
  }
  if (isPrivateOrReservedIP(entry.client_ip)) {
    return t('geo.privateOrReserved');
  }
  return t('geo.unlocated');
}

export function displayContinent(continent: string | undefined, t: Translator) {
  return t(continentKeys[String(continent ?? '').trim()] ?? 'geo.unlocated');
}

export function normalizeCountryCode(value: string | undefined) {
  const raw = String(value ?? '').trim().toUpperCase();
  if (!raw || raw === 'UNKNOWN' || raw === 'UNLOCATED' || raw === '-') {
    return 'UNLOCATED';
  }
  if (countryAliases[raw]) {
    return countryAliases[raw];
  }
  if (raw === 'LOCAL' || raw === 'PRIVATE' || raw === 'LOOPBACK') {
    return 'LOCAL';
  }
  return raw;
}

function normalizeToken(value: string | undefined) {
  return String(value ?? '').trim().toLowerCase().replace(/[-\s]+/g, '_') || 'unknown';
}

function displayGeoCountryName(countryCode: string, countryName: string, t: Translator) {
  if (!countryCode || countryCode === 'UNLOCATED') {
    return '';
  }
  if (countryCode === 'LOCAL') {
    return t('geo.local');
  }
  const localized = displayCountry(countryCode, t);
  if (localized !== t('geo.unlocated')) {
    return localized;
  }
  return countryName || countryCode;
}

function metadataGeo(metadata?: Record<string, unknown>) {
  const geo = metadata?.geo;
  return geo && typeof geo === 'object' && !Array.isArray(geo) ? geo as Record<string, unknown> : undefined;
}

function stringValue(value: unknown) {
  return typeof value === 'string' ? value.trim() : '';
}

function normalizePlaceKey(value: string) {
  return value
    .trim()
    .toLowerCase()
    .replace(/\b(province|city|district|county|prefecture|municipality|autonomous|region|special administrative region)\b/g, '')
    .replace(/省|市|自治区|特别行政区|维吾尔|壮族|回族/g, '')
    .replace(/['’]/g, '')
    .replace(/[^a-z0-9\u4e00-\u9fff]+/g, '');
}

function isPrivateOrReservedIP(value: string | undefined) {
  const ip = String(value ?? '').trim();
  if (!ip) {
    return false;
  }
  if (ip === '::1' || ip === '0:0:0:0:0:0:0:1') {
    return true;
  }
  const ipv4Mapped = ip.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  const ipv4 = ipv4Mapped?.[1] ?? ip;
  const parts = ipv4.split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    const lowered = ip.toLowerCase();
    return lowered.startsWith('fe80:') || lowered.startsWith('fc') || lowered.startsWith('fd');
  }
  const [a, b] = parts;
  return a === 10
    || a === 127
    || a === 0
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168)
    || (a === 192 && b === 0 && parts[2] === 2)
    || (a === 198 && b === 51 && parts[2] === 100)
    || (a === 203 && b === 0 && parts[2] === 113)
    || (a === 169 && b === 254)
    || (a === 100 && b >= 64 && b <= 127)
    || (a === 192 && b === 0)
    || (a === 198 && (b === 18 || b === 19))
    || a >= 224;
}

const cnPlaceNames: Record<string, string> = {
  anhui: '安徽',
  beijing: '北京',
  chongqing: '重庆',
  fujian: '福建',
  gansu: '甘肃',
  guangdong: '广东',
  guangxi: '广西',
  guizhou: '贵州',
  hainan: '海南',
  hebei: '河北',
  heilongjiang: '黑龙江',
  henan: '河南',
  hongkong: '香港',
  hubei: '湖北',
  hunan: '湖南',
  innermongolia: '内蒙古',
  jiangsu: '江苏',
  jiangxi: '江西',
  jilin: '吉林',
  liaoning: '辽宁',
  macau: '澳门',
  ningxia: '宁夏',
  qinghai: '青海',
  shaanxi: '陕西',
  shandong: '山东',
  shanghai: '上海',
  shanxi: '山西',
  sichuan: '四川',
  taiwan: '台湾',
  tianjin: '天津',
  tibet: '西藏',
  xinjiang: '新疆',
  yunnan: '云南',
  zhejiang: '浙江',
  westlake: '西湖区',
  xihu: '西湖区',
  xihudistrict: '西湖区',
  xueyuanroad: '学院路',
  xueyuanrd: '学院路',
  xueyuanlu: '学院路',
  anqing: '安庆',
  bengbu: '蚌埠',
  changchun: '长春',
  changsha: '长沙',
  changzhou: '常州',
  chengdu: '成都',
  dalian: '大连',
  dongguan: '东莞',
  foshan: '佛山',
  fuzhou: '福州',
  guangzhou: '广州',
  guiyang: '贵阳',
  haikou: '海口',
  hangzhou: '杭州',
  harbin: '哈尔滨',
  hefei: '合肥',
  hohhot: '呼和浩特',
  huizhou: '惠州',
  jiaxing: '嘉兴',
  jinan: '济南',
  jinhua: '金华',
  kunming: '昆明',
  lanzhou: '兰州',
  lhasa: '拉萨',
  nanchang: '南昌',
  nanjing: '南京',
  nanning: '南宁',
  nantong: '南通',
  ningbo: '宁波',
  qingdao: '青岛',
  quanzhou: '泉州',
  shenyang: '沈阳',
  shenzhen: '深圳',
  shijiazhuang: '石家庄',
  suzhou: '苏州',
  taizhou: '台州',
  urumqi: '乌鲁木齐',
  wenzhou: '温州',
  wuhan: '武汉',
  wuxi: '无锡',
  xiamen: '厦门',
  xian: '西安',
  xining: '西宁',
  xuzhou: '徐州',
  yinchuan: '银川',
  zhengzhou: '郑州',
  zhongshan: '中山',
  zhuhai: '珠海',
  安徽: '安徽',
  北京: '北京',
  重庆: '重庆',
  福建: '福建',
  甘肃: '甘肃',
  广东: '广东',
  广西: '广西',
  贵州: '贵州',
  海南: '海南',
  河北: '河北',
  黑龙江: '黑龙江',
  河南: '河南',
  湖北: '湖北',
  湖南: '湖南',
  内蒙古: '内蒙古',
  江苏: '江苏',
  江西: '江西',
  吉林: '吉林',
  辽宁: '辽宁',
  宁夏: '宁夏',
  青海: '青海',
  陕西: '陕西',
  山东: '山东',
  上海: '上海',
  山西: '山西',
  四川: '四川',
  天津: '天津',
  西藏: '西藏',
  新疆: '新疆',
  云南: '云南',
  浙江: '浙江',
  杭州: '杭州',
};

const countryAliases: Record<string, string> = {
  CHINA: 'CN',
  'PEOPLE S REPUBLIC OF CHINA': 'CN',
  'PEOPLES REPUBLIC OF CHINA': 'CN',
  'PRC': 'CN',
  中国: 'CN',
  中华人民共和国: 'CN',
  HONGKONG: 'HK',
  'HONG KONG': 'HK',
  MACAU: 'MO',
  MACAO: 'MO',
  TAIWAN: 'TW',
  'UNITED STATES': 'US',
  USA: 'US',
  'UNITED KINGDOM': 'GB',
  UK: 'GB',
};
