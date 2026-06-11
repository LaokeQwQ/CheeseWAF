import { useEffect, useState } from 'react';
import { Button, Checkbox, Form, Input, InputNumber, Select, Switch, Table } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Gauge, ListPlus, PackageCheck, Plus, Trash2 } from 'lucide-react';
import { fetchEdgePolicy, updateEdgePolicy } from '../../api/client';
import type { EdgeConfig } from '../../types/api';

type HeaderRule = EdgeConfig['headers']['rules'][number];
type DurationUnit = 's' | 'm' | 'h' | 'd';
type ByteUnit = 'KB' | 'MB';

const fallback: EdgeConfig = {
  headers: {
    enabled: false,
    rules: [],
  },
  cache: { enabled: false, mode: 'off', ttl: '', status_codes: [], path_prefixes: [], max_body_bytes: 0 },
  compression: { enabled: false, algorithms: [], level: 0, min_bytes: 0, content_types: [] },
};

export default function EdgePage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const { data } = useQuery({ queryKey: ['edge'], queryFn: fetchEdgePolicy, retry: false });
  const [draft, setDraft] = useState<EdgeConfig>(fallback);
  useEffect(() => {
    if (data) {
      setDraft(data);
    }
  }, [data]);
  const edge = draft;
  const mutation = useMutation({
    mutationFn: updateEdgePolicy,
    onSuccess: (saved) => {
      setDraft(saved);
      queryClient.invalidateQueries({ queryKey: ['edge'] });
    },
  });
  const updateHeader = (index: number, patch: Partial<HeaderRule>) => {
    setDraft((current) => ({
      ...current,
      headers: {
        ...current.headers,
        rules: current.headers.rules.map((rule, ruleIndex) => (ruleIndex === index ? { ...rule, ...patch } : rule)),
      },
    }));
  };
  const addHeader = () => {
    setDraft((current) => ({
      ...current,
      headers: {
        ...current.headers,
        rules: [
          ...current.headers.rules,
          {
            id: `header-${Date.now()}`,
            name: '',
            operation: 'set',
            header: '',
            value: '',
            path_prefix: '',
            enabled: true,
          },
        ],
      },
    }));
  };
  const removeHeader = (id: string) => {
    setDraft((current) => ({
      ...current,
      headers: {
        ...current.headers,
        rules: current.headers.rules.filter((rule) => rule.id !== id),
      },
    }));
  };

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('edge.title')}</h1>
          <p>{t('edge.subtitle')}</p>
        </div>
        <Button type="primary" onClick={() => mutation.mutate(edge)} loading={mutation.isPending}>
          {t('common.save')}
        </Button>
      </header>

      <div className="settings-grid">
        <section className="panel">
          <div className="panel-heading"><h2><PackageCheck size={16} /> {t('edge.cache')}</h2></div>
          <Form
            key={`cache-${edge.cache.enabled}-${edge.cache.mode}-${edge.cache.ttl}`}
            layout="vertical"
            initialValues={{
              enabled: edge.cache.enabled,
              mode: edge.cache.mode,
              ttl: durationToNanoseconds(edge.cache.ttl),
              paths: edge.cache.path_prefixes.join(','),
              statusCodes: edge.cache.status_codes.join(','),
              maxBody: edge.cache.max_body_bytes || 2 * 1024 * 1024,
            }}
            onSubmit={(values) => {
              const next = {
              ...edge,
              cache: {
                ...edge.cache,
                enabled: values.enabled,
                mode: values.mode,
                ttl: Number(values.ttl || 0),
                path_prefixes: split(values.paths),
                status_codes: splitNumbers(values.statusCodes),
                max_body_bytes: Number(values.maxBody || 0),
              },
              };
              setDraft(next);
              mutation.mutate(next);
            }}
          >
            <Form.Item label={t('edge.enabled')} field="enabled" triggerPropName="checked"><Switch /></Form.Item>
            <Form.Item label={t('edge.mode')} field="mode" extra={t('edge.modeHint')}>
              <Select>
                <Select.Option value="public">{t('edge.modePublic')}</Select.Option>
                <Select.Option value="private">{t('edge.modePrivate')}</Select.Option>
                <Select.Option value="off">{t('edge.modeOff')}</Select.Option>
              </Select>
            </Form.Item>
            <Form.Item label="TTL" field="ttl" extra={t('edge.ttlHint')}>
              <DurationUnitInput />
            </Form.Item>
            <Form.Item label={t('edge.paths')} field="paths" extra={t('edge.pathsHint')}>
              <Input placeholder="/assets/,/static/" />
            </Form.Item>
            <Form.Item label={t('edge.statusCodes')} field="statusCodes" extra={t('edge.statusCodesHint')}>
              <Input placeholder="200,304" />
            </Form.Item>
            <Form.Item label={t('edge.maxBody')} field="maxBody" extra={t('edge.maxBodyHint')}>
              <ByteUnitInput minBytes={1024} />
            </Form.Item>
            <Button htmlType="submit">{t('common.save')}</Button>
          </Form>
        </section>

        <section className="panel">
          <div className="panel-heading"><h2><Gauge size={16} /> {t('edge.compression')}</h2></div>
          <Form
            key={`compression-${edge.compression.enabled}-${edge.compression.level}-${edge.compression.min_bytes}`}
            layout="vertical"
            initialValues={{
              enabled: edge.compression.enabled,
              algorithms: normalizeAlgorithms(edge.compression.algorithms),
              level: normalizeCompressionLevel(edge.compression.level),
              minBytes: edge.compression.min_bytes || 1024,
              types: edge.compression.content_types.join(','),
            }}
            onSubmit={(values) => {
              const next = {
              ...edge,
              compression: {
                ...edge.compression,
                enabled: values.enabled,
                algorithms: Array.isArray(values.algorithms) ? values.algorithms : [],
                level: Number(values.level || 5),
                min_bytes: Number(values.minBytes || 0),
                content_types: split(values.types),
              },
              };
              setDraft(next);
              mutation.mutate(next);
            }}
          >
            <Form.Item label={t('edge.enabled')} field="enabled" triggerPropName="checked"><Switch /></Form.Item>
            <Form.Item label={t('edge.algorithms')} field="algorithms" extra={t('edge.algorithmsHint')}>
              <Checkbox.Group className="edge-checkbox-group">
                <Checkbox value="br">Brotli (br)</Checkbox>
                <Checkbox value="gzip">Gzip</Checkbox>
              </Checkbox.Group>
            </Form.Item>
            <Form.Item label={t('edge.level')} field="level" extra={t('edge.levelHint')}>
              <Select>
                <Select.Option value={1}>{t('edge.levelFast')}</Select.Option>
                <Select.Option value={5}>{t('edge.levelBalanced')}</Select.Option>
                <Select.Option value={9}>{t('edge.levelCompact')}</Select.Option>
              </Select>
            </Form.Item>
            <Form.Item label={t('edge.minBytes')} field="minBytes" extra={t('edge.minBytesHint')}>
              <ByteUnitInput minBytes={0} defaultUnit="KB" />
            </Form.Item>
            <Form.Item label={t('edge.types')} field="types" extra={t('edge.typesHint')}>
              <Input placeholder="text/,application/json,application/javascript" />
            </Form.Item>
            <Button htmlType="submit">{t('common.save')}</Button>
          </Form>
        </section>
      </div>

      <section className="table-panel">
        <div className="panel-heading">
          <h2><ListPlus size={16} /> {t('edge.headers')}</h2>
          <div className="table-identity">
            <Button icon={<Plus size={14} />} onClick={addHeader}>{t('common.add')}</Button>
            <Button type="primary" onClick={() => mutation.mutate(edge)} loading={mutation.isPending}>{t('common.save')}</Button>
          </div>
        </div>
        <Table
          rowKey="id"
          pagination={false}
          data={edge.headers.rules}
          columns={[
            { title: t('rules.name'), dataIndex: 'name', render: (_: string, record: HeaderRule, index: number) => <Input value={record.name} onChange={(value) => updateHeader(index, { name: value })} /> },
            {
              title: t('edge.operation'),
              dataIndex: 'operation',
              render: (_: string, record: HeaderRule, index: number) => (
                <Select value={record.operation} onChange={(value) => updateHeader(index, { operation: value as HeaderRule['operation'] })}>
                  <Select.Option value="set">set</Select.Option>
                  <Select.Option value="add">add</Select.Option>
                  <Select.Option value="delete">delete</Select.Option>
                </Select>
              ),
            },
            { title: t('edge.header'), dataIndex: 'header', render: (_: string, record: HeaderRule, index: number) => <Input value={record.header} onChange={(value) => updateHeader(index, { header: value })} /> },
            { title: t('edge.value'), dataIndex: 'value', render: (_: string, record: HeaderRule, index: number) => <Input value={record.value} disabled={record.operation === 'delete'} onChange={(value) => updateHeader(index, { value })} /> },
            { title: t('edge.paths'), dataIndex: 'path_prefix', render: (_: string, record: HeaderRule, index: number) => <Input value={record.path_prefix} placeholder="/api/" onChange={(value) => updateHeader(index, { path_prefix: value })} /> },
            { title: t('rules.enabled'), dataIndex: 'enabled', render: (_: boolean, record: HeaderRule, index: number) => <Switch checked={record.enabled} size="small" onChange={(enabled) => updateHeader(index, { enabled })} /> },
            { title: '', dataIndex: 'action', render: (_: unknown, record: HeaderRule) => <Button status="danger" icon={<Trash2 size={14} />} onClick={() => removeHeader(record.id)} /> },
          ]}
        />
      </section>
    </section>
  );
}

function split(value: unknown) {
  return String(value ?? '').split(',').map((item) => item.trim()).filter(Boolean);
}

function splitNumbers(value: unknown) {
  return split(value).map((item) => Number(item)).filter((item) => Number.isInteger(item) && item >= 100 && item <= 599);
}

function normalizeAlgorithms(value: string[]) {
  const out = value.map((item) => (item === 'brotli' ? 'br' : item)).filter((item) => item === 'br' || item === 'gzip');
  return out.length > 0 ? Array.from(new Set(out)) : ['br', 'gzip'];
}

function normalizeCompressionLevel(level: number) {
  if (level <= 1) {
    return 1;
  }
  if (level >= 9) {
    return 9;
  }
  return 5;
}

function DurationUnitInput({ value, onChange }: { value?: number | string; onChange?: (next: number) => void }) {
  const { t } = useTranslation();
  const parts = durationToUnitParts(value);
  const [unit, setUnit] = useState<DurationUnit>(parts.unit);
  useEffect(() => {
    setUnit(parts.unit);
  }, [parts.unit, parts.amount]);

  const emit = (amount: number | string | null | undefined, nextUnit = unit) => {
    const numeric = Math.max(1, Number(amount || 1));
    onChange?.(numeric * durationUnitToNanoseconds(nextUnit));
  };

  return (
    <div className="compound-input">
      <InputNumber min={1} value={parts.amount} onChange={(next) => emit(next)} />
      <Select value={unit} onChange={(next) => { const nextUnit = String(next) as DurationUnit; setUnit(nextUnit); emit(parts.amount, nextUnit); }}>
        <Select.Option value="d">{t('common.days')}</Select.Option>
        <Select.Option value="h">{t('common.hours')}</Select.Option>
        <Select.Option value="m">{t('common.minutes')}</Select.Option>
        <Select.Option value="s">{t('common.seconds')}</Select.Option>
      </Select>
    </div>
  );
}

function ByteUnitInput({
  value,
  onChange,
  minBytes = 0,
  defaultUnit = 'MB',
}: {
  value?: number;
  onChange?: (next: number) => void;
  minBytes?: number;
  defaultUnit?: ByteUnit;
}) {
  const parts = bytesToUnitParts(value, defaultUnit);
  const [unit, setUnit] = useState<ByteUnit>(parts.unit);
  useEffect(() => {
    setUnit(parts.unit);
  }, [parts.unit, parts.amount]);
  const emit = (amount: number | string | null | undefined, nextUnit = unit) => {
    const numeric = Math.max(0, Number(amount || 0));
    onChange?.(Math.max(minBytes, Math.round(numeric * byteUnitMultiplier(nextUnit))));
  };
  return (
    <div className="compound-input">
      <InputNumber min={0} value={parts.amount} precision={parts.unit === 'MB' ? 2 : 0} onChange={(next) => emit(next)} />
      <Select value={unit} onChange={(next) => { const nextUnit = String(next) as ByteUnit; setUnit(nextUnit); emit(parts.amount, nextUnit); }}>
        <Select.Option value="KB">KB</Select.Option>
        <Select.Option value="MB">MB</Select.Option>
      </Select>
    </div>
  );
}

function durationToNanoseconds(value: number | string | undefined) {
  if (typeof value === 'number') {
    return value;
  }
  const raw = String(value ?? '').trim();
  if (!raw) {
    return 5 * durationUnitToNanoseconds('m');
  }
  const numeric = Number.parseFloat(raw);
  if (!Number.isFinite(numeric)) {
    return 5 * durationUnitToNanoseconds('m');
  }
  if (raw.endsWith('d')) {
    return numeric * durationUnitToNanoseconds('d');
  }
  if (raw.endsWith('h')) {
    return numeric * durationUnitToNanoseconds('h');
  }
  if (raw.endsWith('m')) {
    return numeric * durationUnitToNanoseconds('m');
  }
  if (raw.endsWith('s')) {
    return numeric * durationUnitToNanoseconds('s');
  }
  return numeric;
}

function durationToUnitParts(value: number | string | undefined): { amount: number; unit: DurationUnit } {
  const ns = Math.max(1, Number(durationToNanoseconds(value) || 0));
  const units: DurationUnit[] = ['d', 'h', 'm', 's'];
  for (const unit of units) {
    const divisor = durationUnitToNanoseconds(unit);
    if (ns >= divisor && ns % divisor === 0) {
      return { amount: ns / divisor, unit };
    }
  }
  return { amount: Math.max(1, Math.round(ns / durationUnitToNanoseconds('s'))), unit: 's' };
}

function durationUnitToNanoseconds(unit: DurationUnit) {
  switch (unit) {
    case 'd':
      return 24 * 60 * 60 * 1_000_000_000;
    case 'h':
      return 60 * 60 * 1_000_000_000;
    case 'm':
      return 60 * 1_000_000_000;
    default:
      return 1_000_000_000;
  }
}

function bytesToUnitParts(value: number | undefined, defaultUnit: ByteUnit): { amount: number; unit: ByteUnit } {
  const bytes = Math.max(0, Number(value || 0));
  if (bytes === 0) {
    return { amount: 0, unit: defaultUnit };
  }
  if (bytes % byteUnitMultiplier('MB') === 0 || bytes >= byteUnitMultiplier('MB')) {
    return { amount: Number((bytes / byteUnitMultiplier('MB')).toFixed(2)), unit: 'MB' };
  }
  return { amount: Math.round(bytes / byteUnitMultiplier('KB')), unit: 'KB' };
}

function byteUnitMultiplier(unit: ByteUnit) {
  return unit === 'MB' ? 1024 * 1024 : 1024;
}
