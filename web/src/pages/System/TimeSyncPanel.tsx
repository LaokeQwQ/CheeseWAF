import {
  Button,
  Input,
  InputNumber,
  Message as ArcoMessage,
  Select,
  Switch,
  Tag,
} from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Clock3, RefreshCw, RotateCw } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchTimeSyncStatus, reselectTimeSync, syncTimeNow } from '../../api/client';
import type { TimeSyncConfig, TimeSyncStatus } from '../../types/api';
import {
  durationToUnitParts,
  durationUnitToNanoseconds,
  timeSyncQueryKey,
  type DurationUnit,
} from './systemModel';

const selectionUnits = ['m', 'h', 'd'] as const satisfies readonly DurationUnit[];
const syncUnits = ['m', 'h'] as const satisfies readonly DurationUnit[];
const shortUnits = ['ms', 's'] as const satisfies readonly DurationUnit[];
const toleranceUnits = ['ns', 'us', 'ms', 's', 'm'] as const satisfies readonly DurationUnit[];
const sourcesTextareaRows = 5;

type TimeSyncPanelProps = {
  value: TimeSyncConfig;
  onChange: (patch: Partial<TimeSyncConfig>) => void;
};

export default function TimeSyncPanel({ value, onChange }: TimeSyncPanelProps) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [sourcesText, setSourcesText] = useState(() => value.sources.join('\n'));
  const statusQuery = useQuery({
    queryKey: timeSyncQueryKey,
    queryFn: fetchTimeSyncStatus,
    retry: false,
  });

  useEffect(() => {
    setSourcesText((current) => (
      sameSources(parseSources(current), value.sources) ? current : value.sources.join('\n')
    ));
  }, [value.sources]);

  const acceptOperation = (status: TimeSyncStatus, message: string) => {
    queryClient.setQueryData(timeSyncQueryKey, status);
    ArcoMessage.success(message);
  };
  const reselectMutation = useMutation({
    mutationFn: reselectTimeSync,
    onSuccess: (status) => acceptOperation(status, t('system.timeSyncReselectSuccess')),
    onError: (error) => ArcoMessage.error(timeSyncErrorMessage(error, t)),
  });
  const syncMutation = useMutation({
    mutationFn: syncTimeNow,
    onSuccess: (status) => acceptOperation(status, t('system.timeSyncNowSuccess')),
    onError: (error) => ArcoMessage.error(timeSyncErrorMessage(error, t)),
  });

  const status = statusQuery.data;
  const operationPending = reselectMutation.isPending || syncMutation.isPending;
  const operationDisabled = operationPending
    || statusQuery.isLoading
    || statusQuery.isError
    || !value.enabled
    || !status?.enabled
    || status.state === 'synchronizing';

  const patchSources = (next: string) => {
    setSourcesText(next);
    onChange({ sources: parseSources(next) });
  };

  const failuresValue = status
    ? t('system.timeSyncFailuresValue', {
      consecutive: status.consecutive_failures,
      total: status.total_failures,
    })
    : '--';

  return (
    <section className="system-fieldset time-sync-fieldset">
      <header className="fieldset-header-action time-sync-header">
        <div className="time-sync-header-copy">
          <strong><Clock3 size={15} aria-hidden="true" /> {t('system.timeSync')}</strong>
          <span>{t('system.timeSyncHint')}</span>
        </div>
        <div className="time-sync-actions">
          <Button
            size="small"
            icon={<RefreshCw size={14} />}
            loading={reselectMutation.isPending}
            disabled={operationDisabled}
            onClick={() => reselectMutation.mutate()}
          >
            {t('system.timeSyncReselect')}
          </Button>
          <Button
            size="small"
            type="primary"
            icon={<RotateCw size={14} />}
            loading={syncMutation.isPending}
            disabled={operationDisabled}
            onClick={() => syncMutation.mutate()}
          >
            {t('system.timeSyncNow')}
          </Button>
        </div>
      </header>

      {statusQuery.isError && (
        <div className="time-sync-query-error" role="status">
          <span>{t('system.timeSyncStatusUnavailable')}</span>
          <Button size="mini" onClick={() => void statusQuery.refetch()} loading={statusQuery.isFetching}>
            {t('common.retry')}
          </Button>
        </div>
      )}

      <div className="time-sync-runtime">
        <div className="time-sync-runtime-label">{t('system.timeSyncRuntimeStatus')}</div>
        <dl className="time-sync-status-grid" aria-label={t('system.timeSyncRuntimeStatus')}>
          <StatusItem
            label={t('system.timeSyncEnabled')}
            value={status ? <Tag color={status.enabled ? 'green' : 'gray'}>{status.enabled ? t('system.enabled') : t('system.disabled')}</Tag> : '--'}
          />
          <StatusItem
            label={t('common.status')}
            value={<Tag color={timeSyncStateColor(status?.state)}>{timeSyncStateLabel(status, statusQuery.isLoading, t)}</Tag>}
          />
          <StatusItem label={t('system.timeSyncActiveSource')} value={sourceValue(status?.active_source)} emphasized />
          <StatusItem label={t('system.timeSyncCurrentTime')} value={formatTimestamp(status?.current_time, '--')} />

          <StatusItem label={t('system.timeSyncPrimarySource')} value={sourceValue(status?.primary_source)} />
          <StatusItem label={t('system.timeSyncBackupSource')} value={sourceValue(status?.backup_source)} />
          <StatusItem label={t('system.timeSyncOffset')} value={formatMilliseconds(status?.offset_ms, true)} />
          <StatusItem label={t('system.timeSyncRTT')} value={formatMilliseconds(status?.rtt_ms)} />

          <StatusItem label={t('system.timeSyncStratum')} value={status?.stratum ? String(status.stratum) : '--'} />
          <StatusItem label={t('system.timeSyncLastSuccess')} value={formatTimestamp(status?.last_success, t('system.timeSyncNever'))} />
          <StatusItem label={t('system.timeSyncLastAttempt')} value={formatTimestamp(status?.last_attempt, t('system.timeSyncNever'))} />
          <StatusItem label={t('system.timeSyncFailures')} value={failuresValue} />
        </dl>

        {status?.last_error && (
          <div className="time-sync-last-error" role="status">
            <strong>{t('system.timeSyncLastError')}</strong>
            <span>{status.last_error}</span>
          </div>
        )}
      </div>

      <div className="time-sync-config-block">
        <div className="time-sync-config-heading">
          <strong>{t('system.timeSyncConfig')}</strong>
          <span>{t('system.timeSyncConfigHint')}</span>
        </div>
        <div className="site-detail-grid time-sync-config-grid">
          <label className="switch-line time-sync-switch-field">
            <span>{t('system.timeSyncEnabled')}</span>
            <Switch checked={value.enabled} onChange={(enabled) => onChange({ enabled })} />
          </label>
          <label>
            <span>{t('system.timeSyncSamples')}</span>
            <InputNumber
              min={1}
              max={16}
              value={value.samples_per_source}
              onChange={(samples) => {
                const next = Number(samples);
                if (Number.isFinite(next)) onChange({ samples_per_source: next });
              }}
            />
          </label>
          <label>
            <span>{t('system.timeSyncSelectionInterval')}</span>
            <DurationUnitInput
              value={value.selection_interval}
              units={selectionUnits}
              onChange={(selection_interval) => onChange({ selection_interval })}
            />
          </label>
          <label>
            <span>{t('system.timeSyncInterval')}</span>
            <DurationUnitInput
              value={value.sync_interval}
              units={syncUnits}
              onChange={(sync_interval) => onChange({ sync_interval })}
            />
          </label>
          <label>
            <span>{t('system.timeSyncTimeout')}</span>
            <DurationUnitInput
              value={value.timeout}
              units={shortUnits}
              onChange={(timeout) => onChange({ timeout })}
            />
          </label>
          <label>
            <span>{t('system.timeSyncMaxOffset')}</span>
            <DurationUnitInput
              value={value.max_accepted_offset}
              units={toleranceUnits}
              onChange={(max_accepted_offset) => onChange({ max_accepted_offset })}
            />
          </label>
          <label>
            <span>{t('system.timeSyncMaxRootDispersion')}</span>
            <DurationUnitInput
              value={value.max_root_dispersion}
              units={toleranceUnits}
              onChange={(max_root_dispersion) => onChange({ max_root_dispersion })}
            />
          </label>
          <label>
            <span>{t('system.timeSyncConsensusTolerance')}</span>
            <DurationUnitInput
              value={value.consensus_tolerance}
              units={toleranceUnits}
              onChange={(consensus_tolerance) => onChange({ consensus_tolerance })}
            />
          </label>
          <label className="time-sync-sources-field">
            <span>{t('system.timeSyncSources')}</span>
            {/* Prefer fixed rows over autoSize: Arco autoSize yields NaN heights under jsdom. */}
            <Input.TextArea
              value={sourcesText}
              rows={sourcesTextareaRows}
              placeholder={t('system.timeSyncSourcesPlaceholder')}
              onChange={patchSources}
            />
            <em>{t('system.timeSyncSourcesHint')}</em>
          </label>
        </div>
      </div>
    </section>
  );
}

function DurationUnitInput({
  value,
  units,
  onChange,
}: {
  value: number | string;
  units: readonly DurationUnit[];
  onChange: (next: number) => void;
}) {
  const { t } = useTranslation();
  const parts = durationToUnitParts(value, units);
  const emit = (amount: number | string | null | undefined, unit = parts.unit) => {
    const numeric = Number(amount);
    if (Number.isFinite(numeric)) onChange(numeric * durationUnitToNanoseconds(unit));
  };
  return (
    <div className="duration-unit-input time-sync-duration-input">
      <InputNumber value={parts.amount} onChange={(amount) => emit(amount)} />
      <Select value={parts.unit} onChange={(unit) => emit(parts.amount, String(unit) as DurationUnit)}>
        {units.map((unit) => <Select.Option key={unit} value={unit}>{durationUnitLabel(unit, t)}</Select.Option>)}
      </Select>
    </div>
  );
}

function StatusItem({ label, value, emphasized = false }: { label: string; value: ReactNode; emphasized?: boolean }) {
  return (
    <div className={emphasized ? 'time-sync-status-item time-sync-status-item-active' : 'time-sync-status-item'}>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function sourceValue(value?: string) {
  return value?.trim() || '--';
}

function formatMilliseconds(value: number | undefined, signed = false) {
  if (value === undefined || !Number.isFinite(value)) return '--';
  const prefix = signed && value > 0 ? '+' : '';
  return `${prefix}${value} ms`;
}

function formatTimestamp(value: string | undefined, fallback: string) {
  if (!value || value.startsWith('0001-')) return fallback;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function timeSyncStateColor(state?: string) {
  if (state === 'synchronized') return 'green';
  if (state === 'synchronizing') return 'blue';
  if (state === 'local') return 'orange';
  return 'gray';
}

function timeSyncStateLabel(
  status: TimeSyncStatus | undefined,
  loading: boolean,
  t: (key: string) => string,
) {
  if (loading) return t('common.loading');
  switch (status?.state) {
    case 'synchronized':
      return t('system.timeSyncStateSynchronized');
    case 'synchronizing':
      return t('system.timeSyncStateSynchronizing');
    case 'local':
      return t('system.timeSyncStateLocal');
    case 'disabled':
      return t('system.timeSyncStateDisabled');
    default:
      return t('system.timeSyncStateUnknown');
  }
}

function durationUnitLabel(unit: DurationUnit, t: (key: string) => string) {
  if (unit === 'ns' || unit === 'us') return unit;
  if (unit === 'ms') return 'ms';
  if (unit === 's') return t('common.seconds');
  if (unit === 'm') return t('common.minutes');
  if (unit === 'h') return t('common.hours');
  return t('common.days');
}

function parseSources(value: string) {
  return value
    .split(/\r?\n|,/)
    .map((source) => source.trim())
    .filter(Boolean);
}

function sameSources(left: string[], right: string[]) {
  return left.length === right.length && left.every((source, index) => source === right[index]);
}

function timeSyncErrorMessage(error: Error, t: (key: string) => string) {
  switch ((error as Error & { code?: string }).code) {
    case 'TIME_SYNC_DISABLED':
      return t('system.timeSyncErrorDisabled');
    case 'TIME_SYNC_BUSY':
      return t('system.timeSyncErrorBusy');
    case 'TIME_SYNC_UNAVAILABLE':
      return t('system.timeSyncErrorUnavailable');
    case 'TIME_SYNC_FAILED':
      return t('system.timeSyncErrorFailed');
    default:
      return error.message;
  }
}
