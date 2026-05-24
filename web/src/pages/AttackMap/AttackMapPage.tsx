import { Table, Tag } from '@arco-design/web-react';
import { useTranslation } from 'react-i18next';

const regions = [
  { key: 'us', country: 'US', attacks: 1842, top: 'SQLi', x: 22, y: 38 },
  { key: 'de', country: 'DE', attacks: 734, top: 'XSS', x: 49, y: 34 },
  { key: 'sg', country: 'SG', attacks: 421, top: 'SSRF', x: 71, y: 58 },
  { key: 'br', country: 'BR', attacks: 266, top: 'LFI', x: 36, y: 70 },
  { key: 'jp', country: 'JP', attacks: 318, top: 'RCE', x: 82, y: 43 },
];

export default function AttackMapPage() {
  const { t } = useTranslation();
  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('attackMap.title')}</h1>
          <p>{t('attackMap.subtitle')}</p>
        </div>
      </header>
      <section className="map-canvas">
        <div className="map-grid-lines" />
        {regions.map((region) => (
          <span
            key={region.key}
            className="map-marker"
            style={{ left: `${region.x}%`, top: `${region.y}%` }}
            title={`${region.country} ${region.attacks}`}
          >
            <i />
            <strong>{region.country}</strong>
          </span>
        ))}
      </section>
      <section className="table-panel">
        <Table
          rowKey="key"
          pagination={false}
          data={regions}
          columns={[
            { title: t('attackMap.country'), dataIndex: 'country' },
            { title: t('attackMap.attacks'), dataIndex: 'attacks' },
            { title: t('attackMap.top'), dataIndex: 'top', render: (top: string) => <Tag color="orange">{top}</Tag> },
          ]}
        />
      </section>
    </section>
  );
}
