#!/usr/bin/env node
/**
 * Pack the licensed Gaode world countries GeoJSON (GS(2021)648) into
 * public/map/world/gaode_world.geojson.gz with iso2 identifiers.
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = fileURLToPath(new URL('..', import.meta.url));
const source = process.argv[2];
if (!source) {
  console.error('usage: node scripts/pack-gaode-world.mjs /path/to/gaode-world.geojson');
  process.exit(1);
}

const ISO3_TO_2 = {
  ABW: 'AW', AFG: 'AF', AGO: 'AO', AIA: 'AI', ALA: 'AX', ALB: 'AL', AND: 'AD', ANT: 'AN',
  ARE: 'AE', ARG: 'AR', ARM: 'AM', ASM: 'AS', ATA: 'AQ', ATF: 'TF', ATG: 'AG', AUS: 'AU',
  AUT: 'AT', AZE: 'AZ', BDI: 'BI', BEL: 'BE', BEN: 'BJ', BES: 'BQ', BFA: 'BF', BGD: 'BD',
  BGR: 'BG', BHR: 'BH', BHS: 'BS', BIH: 'BA', BLM: 'BL', BLR: 'BY', BLZ: 'BZ', BMU: 'BM',
  BOL: 'BO', BRA: 'BR', BRB: 'BB', BRN: 'BN', BTN: 'BT', BVT: 'BV', BWA: 'BW', CAF: 'CF',
  CAN: 'CA', CCK: 'CC', CHE: 'CH', CHL: 'CL', CHN: 'CN', CIV: 'CI', CMR: 'CM', COD: 'CD',
  COG: 'CG', COK: 'CK', COL: 'CO', COM: 'KM', CPV: 'CV', CRI: 'CR', CUB: 'CU', CUW: 'CW',
  CXR: 'CX', CYM: 'KY', CYP: 'CY', CZE: 'CZ', DEU: 'DE', DJI: 'DJ', DMA: 'DM', DNK: 'DK',
  DOM: 'DO', DZA: 'DZ', ECU: 'EC', EGY: 'EG', ERI: 'ER', ESH: 'EH', ESP: 'ES', EST: 'EE',
  ETH: 'ET', FIN: 'FI', FJI: 'FJ', FLK: 'FK', FRA: 'FR', FRO: 'FO', FSM: 'FM', GAB: 'GA',
  GBR: 'GB', GEO: 'GE', GGY: 'GG', GHA: 'GH', GIB: 'GI', GIN: 'GN', GLP: 'GP', GMB: 'GM',
  GNB: 'GW', GNQ: 'GQ', GRC: 'GR', GRD: 'GD', GRL: 'GL', GTM: 'GT', GUF: 'GF', GUM: 'GU',
  GUY: 'GY', HKG: 'HK', HMD: 'HM', HND: 'HN', HRV: 'HR', HTI: 'HT', HUN: 'HU', IDN: 'ID',
  IMN: 'IM', IND: 'IN', IOT: 'IO', IRL: 'IE', IRN: 'IR', IRQ: 'IQ', ISL: 'IS', ISR: 'IL',
  ITA: 'IT', JAM: 'JM', JEY: 'JE', JOR: 'JO', JPN: 'JP', KAZ: 'KZ', KEN: 'KE', KGZ: 'KG',
  KHM: 'KH', KIR: 'KI', KNA: 'KN', KOR: 'KR', KWT: 'KW', LAO: 'LA', LBN: 'LB', LBR: 'LR',
  LBY: 'LY', LCA: 'LC', LIE: 'LI', LKA: 'LK', LSO: 'LS', LTU: 'LT', LUX: 'LU', LVA: 'LV',
  MAC: 'MO', MAF: 'MF', MAR: 'MA', MCO: 'MC', MDA: 'MD', MDG: 'MG', MDV: 'MV', MEX: 'MX',
  MHL: 'MH', MKD: 'MK', MLI: 'ML', MLT: 'MT', MMR: 'MM', MNE: 'ME', MNG: 'MN', MNP: 'MP',
  MOZ: 'MZ', MRT: 'MR', MSR: 'MS', MTQ: 'MQ', MUS: 'MU', MWI: 'MW', MYS: 'MY', MYT: 'YT',
  NAM: 'NA', NCL: 'NC', NER: 'NE', NFK: 'NF', NGA: 'NG', NIC: 'NI', NIU: 'NU', NLD: 'NL',
  NOR: 'NO', NPL: 'NP', NRU: 'NR', NZL: 'NZ', OMN: 'OM', PAK: 'PK', PAN: 'PA', PCN: 'PN',
  PER: 'PE', PHL: 'PH', PLW: 'PW', PNG: 'PG', POL: 'PL', PRI: 'PR', PRK: 'KP', PRT: 'PT',
  PRY: 'PY', PSE: 'PS', PYF: 'PF', QAT: 'QA', REU: 'RE', ROU: 'RO', RUS: 'RU', RWA: 'RW',
  SAU: 'SA', SDN: 'SD', SEN: 'SN', SGP: 'SG', SGS: 'GS', SHN: 'SH', SJM: 'SJ', SLB: 'SB',
  SLE: 'SL', SLV: 'SV', SMR: 'SM', SOM: 'SO', SPM: 'PM', SRB: 'RS', SSD: 'SS', STP: 'ST',
  SUR: 'SR', SVK: 'SK', SVN: 'SI', SWE: 'SE', SWZ: 'SZ', SXM: 'SX', SYC: 'SC', SYR: 'SY',
  TCA: 'TC', TCD: 'TD', TGO: 'TG', THA: 'TH', TJK: 'TJ', TKL: 'TK', TKM: 'TM', TLS: 'TL',
  TON: 'TO', TTO: 'TT', TUN: 'TN', TUR: 'TR', TUV: 'TV', TWN: 'TW', TZA: 'TZ', UGA: 'UG',
  UKR: 'UA', UMI: 'UM', URY: 'UY', USA: 'US', UZB: 'UZ', VAT: 'VA', VCT: 'VC', VEN: 'VE',
  VGB: 'VG', VIR: 'VI', VNM: 'VN', VUT: 'VU', WLF: 'WF', WSM: 'WS', YEM: 'YE', ZAF: 'ZA',
  ZMB: 'ZM', ZWE: 'ZW',
  ROM: 'RO', TMP: 'TL', SAB: 'BQ', MAH: 'SX', SES: 'BQ', CLI: 'FR', SF: 'ZA',
};

const raw = JSON.parse(readFileSync(source, 'utf8'));
const features = Array.isArray(raw?.features) ? raw.features : [];
const packed = [];
const unmapped = [];
for (const feature of features) {
  const props = feature?.properties ?? {};
  const iso3 = String(props.SOC ?? '').trim().toUpperCase();
  if (!iso3) {
    continue;
  }
  const iso2 = ISO3_TO_2[iso3] ?? '';
  if (!iso2) {
    unmapped.push(iso3);
  }
  const id = iso2 || iso3;
  packed.push({
    type: 'Feature',
    id,
    properties: {
      name: String(props.NAME_CHN ?? props.NAME_ENG ?? id),
      name_en: String(props.NAME_ENG ?? ''),
      iso2: iso2 || id,
      iso3,
    },
    geometry: feature.geometry,
  });
}

const collection = { type: 'FeatureCollection', features: packed };
const outDir = path.join(projectRoot, 'public', 'map', 'world');
mkdirSync(outDir, { recursive: true });
const outPath = path.join(outDir, 'gaode_world.geojson.gz');
writeFileSync(outPath, gzipSync(Buffer.from(JSON.stringify(collection))));
const china = packed.find((item) => item.id === 'CN');
console.log(`packed ${packed.length} countries -> ${path.relative(projectRoot, outPath)} (${(readFileSync(outPath).length / 1024).toFixed(1)} KiB)`);
console.log(`china feature: ${china ? 'yes' : 'NO'}`);
if (unmapped.length) {
  console.warn(`unmapped ISO3: ${[...new Set(unmapped)].join(',')}`);
}
if (!china) {
  process.exitCode = 1;
}
