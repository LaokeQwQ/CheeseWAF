import { Progress, Tag } from '@arco-design/web-react';
import { motion } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import { Cpu, HardDrive, Network, ShieldCheck, Zap } from 'lucide-react';
import { listItemVariants, listVariants } from '../../animations/variants';

const traffic = [34, 48, 42, 56, 61, 55, 72, 78, 64, 83, 76, 88];
const threats = [
  { name: 'SQLi', value: 42, color: 'var(--accent-danger)' },
  { name: 'XSS', value: 28, color: 'var(--accent-warning)' },
  { name: 'RCE', value: 18, color: 'var(--accent-purple)' },
  { name: 'Bot', value: 12, color: 'var(--accent-info)' },
];

const events = [
  { trace: 'cw-9fa31c', ip: '203.0.113.18', type: 'SQLi', action: 'block' },
  { trace: 'cw-802c7e', ip: '198.51.100.77', type: 'XSS', action: 'block' },
  { trace: 'cw-441dda', ip: '192.0.2.46', type: 'Bot', action: 'monitor' },
];

export default function DashboardPage() {
  const { t } = useTranslation();

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('dashboard.title')}</h1>
          <p>{t('dashboard.subtitle')}</p>
        </div>
        <Tag color="green" icon={<ShieldCheck size={14} />}>
          {t('common.online')}
        </Tag>
      </header>

      <motion.div className="metric-grid" variants={listVariants} initial="initial" animate="enter">
        {[
          { label: t('shell.requests'), value: '18.4k', delta: '+12.8%', icon: Zap },
          { label: t('shell.attacks'), value: '327', delta: '-4.1%', icon: ShieldCheck },
          { label: t('shell.latency'), value: '3.8ms', delta: 'P99', icon: Network },
          { label: t('dashboard.sites'), value: '6', delta: '5 TLS', icon: HardDrive },
        ].map((item) => {
          const Icon = item.icon;
          return (
            <motion.article className="metric-card" key={item.label} variants={listItemVariants}>
              <Icon size={20} />
              <span>{item.label}</span>
              <strong>{item.value}</strong>
              <em>{item.delta}</em>
            </motion.article>
          );
        })}
      </motion.div>

      <div className="dashboard-grid">
        <section className="panel panel-wide">
          <div className="panel-heading">
            <h2>{t('dashboard.traffic')}</h2>
            <span>60m</span>
          </div>
          <div className="bar-chart" aria-label={t('dashboard.traffic')}>
            {traffic.map((value, index) => (
              <motion.span
                key={`${value}-${index}`}
                initial={{ height: 0 }}
                animate={{ height: `${value}%` }}
                transition={{ delay: index * 0.02, duration: 0.28 }}
              />
            ))}
          </div>
        </section>

        <section className="panel">
          <div className="panel-heading">
            <h2>{t('dashboard.threatMix')}</h2>
          </div>
          <div className="threat-list">
            {threats.map((threat) => (
              <div className="threat-row" key={threat.name}>
                <span>{threat.name}</span>
                <Progress
                  percent={threat.value}
                  showText={false}
                  color={threat.color}
                  size="small"
                />
                <strong>{threat.value}%</strong>
              </div>
            ))}
          </div>
        </section>

        <section className="panel">
          <div className="panel-heading">
            <h2>{t('dashboard.resources')}</h2>
          </div>
          <div className="resource-stack">
            <div>
              <Cpu size={18} />
              <span>CPU</span>
              <Progress percent={28} size="small" showText={false} />
              <strong>28%</strong>
            </div>
            <div>
              <HardDrive size={18} />
              <span>RAM</span>
              <Progress percent={46} size="small" showText={false} />
              <strong>46%</strong>
            </div>
          </div>
        </section>

        <section className="panel panel-wide">
          <div className="panel-heading">
            <h2>{t('dashboard.events')}</h2>
          </div>
          <div className="event-list">
            {events.map((event) => (
              <div className="event-row" key={event.trace}>
                <code>{event.trace}</code>
                <span>{event.ip}</span>
                <Tag color={event.type === 'SQLi' ? 'red' : 'orange'}>{event.type}</Tag>
                <Tag color={event.action === 'block' ? 'red' : 'blue'}>
                  {event.action === 'block' ? t('common.block') : t('common.monitor')}
                </Tag>
              </div>
            ))}
          </div>
        </section>
      </div>
    </section>
  );
}
