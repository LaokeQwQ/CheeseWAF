import { Tag } from '@arco-design/web-react';
import { Activity, Gauge, Layers3, ShieldCheck } from 'lucide-react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { displayAction, displayCategory, displaySeverity } from '../utils/display';

type WAFPolicyDecision = {
  level?: string;
  action?: string;
  reason?: string;
  paranoiaLevel?: number;
  minimumSeverity?: string;
  minimumConfidence?: number;
  minimumRiskScore?: number;
  riskScore?: number;
  evidenceCount?: number;
  resultSeverity?: string;
  resultConfidence?: number;
  detectorAction?: string;
  detectorCategory?: string;
  detectorId?: string;
};

type PolicyDecisionCardProps = {
  metadata?: Record<string, unknown>;
  compact?: boolean;
};

export default function PolicyDecisionCard({ metadata, compact = false }: PolicyDecisionCardProps) {
  const { t } = useTranslation();
  const decision = getWAFPolicyDecision(metadata);
  if (!decision) {
    return null;
  }

  const reason = policyReasonLabel(decision, t);
  const resultLabel = [
    decision.resultSeverity ? displaySeverity(decision.resultSeverity, t) : '',
    formatConfidence(decision.resultConfidence),
  ].filter(Boolean).join(' / ') || '-';

  return (
    <section className={`policy-decision-card${compact ? ' policy-decision-card-compact' : ''}`} aria-label={t('logs.policyDecision')}>
      <header className="policy-decision-head">
        <div>
          <span><ShieldCheck size={16} /> {t('logs.policyDecision')}</span>
          <strong>{reason}</strong>
        </div>
        <div className="policy-decision-tags">
          <Tag color={actionColor(decision.action)}>{displayAction(decision.action, t)}</Tag>
          <Tag>{policyLevelLabel(decision.level, t)}</Tag>
          {decision.paranoiaLevel ? <Tag color="arcoblue">{t('logs.policyParanoiaLevel', { level: decision.paranoiaLevel })}</Tag> : null}
        </div>
      </header>

      <div className="policy-decision-metrics">
        <PolicyMetric
          icon={<Gauge size={15} />}
          label={t('logs.policyRiskScore')}
          value={formatRiskScore(decision.riskScore, decision.minimumRiskScore)}
        />
        <PolicyMetric
          icon={<Activity size={15} />}
          label={t('logs.policyConfidence')}
          value={resultLabel}
        />
        <PolicyMetric
          icon={<Layers3 size={15} />}
          label={t('logs.policyEvidenceCount')}
          value={formatNumber(decision.evidenceCount)}
        />
      </div>

      <footer className="policy-decision-foot">
        <span>{t('logs.policyThreshold', {
          severity: displaySeverity(decision.minimumSeverity, t),
          confidence: formatConfidence(decision.minimumConfidence),
          risk: formatNumber(decision.minimumRiskScore),
        })}</span>
        {decision.detectorId ? (
          <span>{t('logs.policyDetector', {
            detector: decision.detectorId,
            category: displayCategory(decision.detectorCategory, t),
          })}</span>
        ) : null}
      </footer>
    </section>
  );
}

function PolicyMetric({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="policy-decision-metric">
      <span>{icon}{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export function getWAFPolicyDecision(metadata?: Record<string, unknown>): WAFPolicyDecision | null {
  const raw = metadata?.waf_policy_decision;
  if (!isRecord(raw)) {
    return null;
  }
  return {
    level: readString(raw.level),
    action: readString(raw.action),
    reason: readString(raw.reason),
    paranoiaLevel: readNumber(raw.paranoia_level),
    minimumSeverity: readString(raw.minimum_severity),
    minimumConfidence: readNumber(raw.minimum_confidence),
    minimumRiskScore: readNumber(raw.minimum_risk_score),
    riskScore: readNumber(raw.risk_score),
    evidenceCount: readNumber(raw.evidence_count),
    resultSeverity: readString(raw.result_severity),
    resultConfidence: readNumber(raw.result_confidence),
    detectorAction: readString(raw.detector_action),
    detectorCategory: readString(raw.detector_category),
    detectorId: readString(raw.detector_id),
  };
}

function policyReasonLabel(decision: WAFPolicyDecision, t: (key: string, options?: Record<string, unknown>) => string) {
  const reason = String(decision.reason ?? '').trim().toLowerCase();
  if (reason === 'detected below policy threshold') {
    return t('logs.policyReasonBelowThreshold');
  }
  if (reason === 'no detection result') {
    return t('logs.policyReasonNoDetection');
  }
  if (reason === 'web attack protection disabled') {
    return t('logs.policyReasonDisabled');
  }
  if (reason === 'severity and confidence meet policy threshold') {
    return t('logs.policyReasonDirectThreshold');
  }
  if (reason === 'aggregate risk score meets policy threshold') {
    return t('logs.policyReasonAggregateThreshold');
  }
  if (reason.startsWith('detector requested ')) {
    return t('logs.policyReasonDetectorRequested', {
      action: displayAction(reason.replace('detector requested ', ''), t),
    });
  }
  return t('logs.policyReasonOther');
}

function policyLevelLabel(level: string | undefined, t: (key: string, options?: Record<string, unknown>) => string) {
  switch (String(level ?? '').trim().toLowerCase()) {
    case 'off':
      return t('logs.policyLevelOff');
    case 'low':
      return t('logs.policyLevelLow');
    case 'high':
      return t('logs.policyLevelHigh');
    case 'strict':
      return t('logs.policyLevelStrict');
    case 'smart':
    case '':
      return t('logs.policyLevelSmart');
    default:
      return level ?? t('logs.policyLevelSmart');
  }
}

function actionColor(action: string | undefined) {
  switch (String(action ?? '').trim().toLowerCase()) {
    case 'block':
      return 'red';
    case 'challenge':
      return 'orange';
    case 'allow':
    case 'pass':
      return 'green';
    default:
      return 'arcoblue';
  }
}

function formatRiskScore(score: number | undefined, threshold: number | undefined) {
  if (score === undefined && threshold === undefined) {
    return '-';
  }
  if (threshold === undefined) {
    return formatNumber(score);
  }
  return `${formatNumber(score)} / ${formatNumber(threshold)}`;
}

function formatConfidence(value: number | undefined) {
  if (value === undefined) {
    return '';
  }
  const percent = value <= 1 ? value * 100 : value;
  return `${Math.round(percent)}%`;
}

function formatNumber(value: number | undefined) {
  return typeof value === 'number' && Number.isFinite(value) ? String(Math.round(value)) : '-';
}

function readString(value: unknown) {
  return typeof value === 'string' ? value.trim() : undefined;
}

function readNumber(value: unknown) {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}
