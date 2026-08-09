import { useEffect, useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Gauge, ListPlus, PackageCheck, Plus, Trash2 } from 'lucide-react';
import {
  Button,
  Checkbox,
  Empty,
  Input,
  Label,
  Popover,
  PopoverContent,
  PopoverTrigger,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  toast,
} from '@/components/ui';
import { fetchEdgePolicy, updateEdgePolicy } from '../../api/client';
import { useServerDraft } from '../../hooks/useServerDraft';
import type { EdgeConfig } from '../../types/api';

type HeaderRule = EdgeConfig['headers']['rules'][number];
type DurationUnit = 's' | 'm' | 'h' | 'd';
type ByteUnit = 'KB' | 'MB';
const statusCodeChoices = ['2xx', '3xx', '4xx', '5xx', '200', '201', '204', '301', '302', '304', '400', '401', '403', '404', '429', '500', '502', '503'];

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
  const edgeQuery = useQuery({ queryKey: ['edge'], queryFn: fetchEdgePolicy, retry: false });
  const { data, isError, isFetching, isSuccess, isLoading, error, refetch } = edgeQuery;
  const { draft, setDraft, markClean } = useServerDraft(data);
  const edge = draft ?? fallback;
  const mutation = useMutation({
    mutationFn: updateEdgePolicy,
    onSuccess: (saved) => {
      markClean(saved);
      queryClient.invalidateQueries({ queryKey: ['edge'] });
      toast.success(t('common.saved'));
    },
    onError: (mutationError) => toast.error(mutationError.message),
  });

  // Local form state for cache / compression panels (synced from server draft)
  const [cacheForm, setCacheForm] = useState({
    enabled: edge.cache.enabled,
    mode: edge.cache.mode || 'off',
    ttl: durationToNanoseconds(edge.cache.ttl),
    paths: (edge.cache.path_prefixes ?? []).join(','),
    statusCodes: statusCodesToChoices(edge.cache.status_codes),
    maxBody: edge.cache.max_body_bytes || 2 * 1024 * 1024,
  });
  const [compressionForm, setCompressionForm] = useState({
    enabled: edge.compression.enabled,
    algorithms: normalizeAlgorithms(edge.compression.algorithms),
    level: normalizeCompressionLevel(edge.compression.level),
    minBytes: edge.compression.min_bytes || 1024,
    types: (edge.compression.content_types ?? []).join(','),
  });

  useEffect(() => {
    if (!data) return;
    setCacheForm({
      enabled: data.cache.enabled,
      mode: data.cache.mode || 'off',
      ttl: durationToNanoseconds(data.cache.ttl),
      paths: (data.cache.path_prefixes ?? []).join(','),
      statusCodes: statusCodesToChoices(data.cache.status_codes),
      maxBody: data.cache.max_body_bytes || 2 * 1024 * 1024,
    });
    setCompressionForm({
      enabled: data.compression.enabled,
      algorithms: normalizeAlgorithms(data.compression.algorithms),
      level: normalizeCompressionLevel(data.compression.level),
      minBytes: data.compression.min_bytes || 1024,
      types: (data.compression.content_types ?? []).join(','),
    });
  }, [data]);

  const pushCacheToDraft = (values: typeof cacheForm) => {
    setDraft((current) => {
      const base = current ?? fallback;
      return {
        ...base,
        cache: {
          ...base.cache,
          enabled: Boolean(values.enabled),
          mode: String(values.mode ?? base.cache.mode),
          ttl: Number(values.ttl || 0),
          path_prefixes: split(values.paths),
          status_codes: parseStatusCodeChoices(values.statusCodes),
          max_body_bytes: Number(values.maxBody || 0),
        },
      };
    });
  };

  const pushCompressionToDraft = (values: typeof compressionForm) => {
    setDraft((current) => {
      const base = current ?? fallback;
      return {
        ...base,
        compression: {
          ...base.compression,
          enabled: Boolean(values.enabled),
          algorithms: Array.isArray(values.algorithms) ? values.algorithms.map(String) : [],
          level: Number(values.level || 5),
          min_bytes: Number(values.minBytes || 0),
          content_types: split(values.types),
        },
      };
    });
  };

  const updateHeader = (index: number, patch: Partial<HeaderRule>) => {
    setDraft((current) => {
      const base = current ?? fallback;
      return {
        ...base,
        headers: {
          ...base.headers,
          rules: base.headers.rules.map((rule, ruleIndex) => (ruleIndex === index ? { ...rule, ...patch } : rule)),
        },
      };
    });
  };
  const addHeader = () => {
    setDraft((current) => {
      const base = current ?? fallback;
      return {
        ...base,
        headers: {
          ...base.headers,
          rules: [
            ...base.headers.rules,
            {
              id: `header-${Date.now()}-${Math.random().toString(16).slice(2)}`,
              name: '',
              operation: 'set',
              header: '',
              value: '',
              path_prefix: '',
              enabled: true,
            },
          ],
        },
      };
    });
  };
  const removeHeader = (id: string) => {
    setDraft((current) => {
      const base = current ?? fallback;
      return {
        ...base,
        headers: {
          ...base.headers,
          rules: base.headers.rules.filter((rule) => rule.id !== id),
        },
      };
    });
  };

  const saveDraft = () => {
    if (!isSuccess && !draft) {
      return;
    }
    // Ensure latest form values are in draft
    const next: EdgeConfig = {
      ...edge,
      cache: {
        ...edge.cache,
        enabled: cacheForm.enabled,
        mode: cacheForm.mode,
        ttl: Number(cacheForm.ttl || 0),
        path_prefixes: split(cacheForm.paths),
        status_codes: parseStatusCodeChoices(cacheForm.statusCodes),
        max_body_bytes: Number(cacheForm.maxBody || 0),
      },
      compression: {
        ...edge.compression,
        enabled: compressionForm.enabled,
        algorithms: Array.isArray(compressionForm.algorithms) ? compressionForm.algorithms : [],
        level: Number(compressionForm.level || 5),
        min_bytes: Number(compressionForm.minBytes || 0),
        content_types: split(compressionForm.types),
      },
    };
    setDraft(next);
    mutation.mutate(next);
  };

  const saveCache = (event: FormEvent) => {
    event.preventDefault();
    const next: EdgeConfig = {
      ...edge,
      cache: {
        ...edge.cache,
        enabled: cacheForm.enabled,
        mode: cacheForm.mode,
        ttl: Number(cacheForm.ttl || 0),
        path_prefixes: split(cacheForm.paths),
        status_codes: parseStatusCodeChoices(cacheForm.statusCodes),
        max_body_bytes: Number(cacheForm.maxBody || 0),
      },
    };
    setDraft(next);
    mutation.mutate(next);
  };

  const saveCompression = (event: FormEvent) => {
    event.preventDefault();
    const next: EdgeConfig = {
      ...edge,
      compression: {
        ...edge.compression,
        enabled: compressionForm.enabled,
        algorithms: Array.isArray(compressionForm.algorithms) ? compressionForm.algorithms : [],
        level: Number(compressionForm.level || 5),
        min_bytes: Number(compressionForm.minBytes || 0),
        content_types: split(compressionForm.types),
      },
    };
    setDraft(next);
    mutation.mutate(next);
  };

  if (isLoading && !draft) {
    return (
      <section className="page-surface">
        <header className="page-header">
          <div>
            <h1>{t('edge.title')}</h1>
            <p>{t('edge.subtitle')}</p>
          </div>
        </header>
        <div className="empty-state" role="status">{t('common.loading')}</div>
      </section>
    );
  }

  if (isError && !draft) {
    return (
      <section className="page-surface">
        <header className="page-header">
          <div>
            <h1>{t('edge.title')}</h1>
            <p>{t('edge.subtitle')}</p>
          </div>
        </header>
        <div className="query-error-state" role="alert">
          <div className="query-error-state__body">
            <strong>{t('common.loadFailed')}</strong>
            {error instanceof Error ? <span>{error.message}</span> : null}
          </div>
          <Button size="sm" loading={isFetching} onClick={() => { void refetch(); }}>{t('common.retry')}</Button>
        </div>
      </section>
    );
  }

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('edge.title')}</h1>
          <p>{t('edge.subtitle')}</p>
        </div>
        <Button onClick={saveDraft} loading={mutation.isPending} disabled={!isSuccess && !draft}>
          {t('common.save')}
        </Button>
      </header>

      {isError && (
        <div className="query-error-state" role="alert">
          <div className="query-error-state__body">
            <strong>{t('common.loadFailed')}</strong>
            {error instanceof Error ? <span>{error.message}</span> : null}
          </div>
          <Button size="sm" loading={isFetching} onClick={() => { void refetch(); }}>{t('common.retry')}</Button>
        </div>
      )}

      <div className="edge-settings-grid">
        <section className="panel">
          <div className="panel-heading"><h2><PackageCheck size={16} /> {t('edge.cache')}</h2></div>
          <form className="edge-form" onSubmit={saveCache}>
            <div className="field-stack">
              <Label>{t('edge.enabled')}</Label>
              <Switch
                checked={cacheForm.enabled}
                onCheckedChange={(enabled) => {
                  const next = { ...cacheForm, enabled };
                  setCacheForm(next);
                  pushCacheToDraft(next);
                }}
              />
            </div>
            <div className="field-stack">
              <Label>{t('edge.mode')}</Label>
              <Select
                value={cacheForm.mode || 'off'}
                onValueChange={(mode) => {
                  const next = { ...cacheForm, mode };
                  setCacheForm(next);
                  pushCacheToDraft(next);
                }}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {!['public', 'private', 'off'].includes(cacheForm.mode) && cacheForm.mode ? (
                    <SelectItem value={cacheForm.mode}>{cacheForm.mode}</SelectItem>
                  ) : null}
                  <SelectItem value="public">{t('edge.modePublic')}</SelectItem>
                  <SelectItem value="private">{t('edge.modePrivate')}</SelectItem>
                  <SelectItem value="off">{t('edge.modeOff')}</SelectItem>
                </SelectContent>
              </Select>
              <span className="field-help">{t('edge.modeHint')}</span>
            </div>
            <div className="field-stack">
              <Label>TTL</Label>
              <DurationUnitInput
                value={cacheForm.ttl}
                onChange={(ttl) => {
                  const next = { ...cacheForm, ttl };
                  setCacheForm(next);
                  pushCacheToDraft(next);
                }}
              />
              <span className="field-help">{t('edge.ttlHint')}</span>
            </div>
            <div className="field-stack">
              <Label>{t('edge.paths')}</Label>
              <Input
                placeholder="/assets/,/static/"
                value={cacheForm.paths}
                onChange={(e) => {
                  const next = { ...cacheForm, paths: e.target.value };
                  setCacheForm(next);
                  pushCacheToDraft(next);
                }}
              />
              <span className="field-help">{t('edge.pathsHint')}</span>
            </div>
            <div className="field-stack">
              <Label>{t('edge.statusCodes')}</Label>
              <StatusCodeSelector
                value={cacheForm.statusCodes}
                onChange={(statusCodes) => {
                  const next = { ...cacheForm, statusCodes };
                  setCacheForm(next);
                  pushCacheToDraft(next);
                }}
              />
              <span className="field-help">{t('edge.statusCodesHint')}</span>
            </div>
            <div className="field-stack">
              <Label>{t('edge.maxBody')}</Label>
              <ByteUnitInput
                value={cacheForm.maxBody}
                minBytes={1024}
                onChange={(maxBody) => {
                  const next = { ...cacheForm, maxBody };
                  setCacheForm(next);
                  pushCacheToDraft(next);
                }}
              />
              <span className="field-help">{t('edge.maxBodyHint')}</span>
            </div>
            <div className="form-action-row"><Button type="submit">{t('common.save')}</Button></div>
          </form>
        </section>

        <section className="panel">
          <div className="panel-heading"><h2><Gauge size={16} /> {t('edge.compression')}</h2></div>
          <form className="edge-form" onSubmit={saveCompression}>
            <div className="field-stack">
              <Label>{t('edge.enabled')}</Label>
              <Switch
                checked={compressionForm.enabled}
                onCheckedChange={(enabled) => {
                  const next = { ...compressionForm, enabled };
                  setCompressionForm(next);
                  pushCompressionToDraft(next);
                }}
              />
            </div>
            <div className="field-stack">
              <Label>{t('edge.algorithms')}</Label>
              <div className="edge-checkbox-group flex gap-4">
                {(['gzip', 'br'] as const).map((algo) => (
                  <label key={algo} className="flex items-center gap-2 text-sm">
                    <Checkbox
                      checked={compressionForm.algorithms.includes(algo)}
                      onCheckedChange={(checked) => {
                        const algorithms = checked
                          ? Array.from(new Set([...compressionForm.algorithms, algo]))
                          : compressionForm.algorithms.filter((item) => item !== algo);
                        const next = { ...compressionForm, algorithms };
                        setCompressionForm(next);
                        pushCompressionToDraft(next);
                      }}
                    />
                    {algo === 'gzip' ? 'Gzip' : 'Brotli (br)'}
                  </label>
                ))}
              </div>
              <span className="field-help">{t('edge.algorithmsHint')}</span>
            </div>
            <div className="field-stack">
              <Label>{t('edge.level')}</Label>
              <Select
                value={String(compressionForm.level)}
                onValueChange={(level) => {
                  const next = { ...compressionForm, level: Number(level) };
                  setCompressionForm(next);
                  pushCompressionToDraft(next);
                }}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">{t('edge.levelFast')}</SelectItem>
                  <SelectItem value="3">{t('edge.levelLight')}</SelectItem>
                  <SelectItem value="5">{t('edge.levelBalanced')}</SelectItem>
                  <SelectItem value="7">{t('edge.levelStrong')}</SelectItem>
                  <SelectItem value="9">{t('edge.levelCompact')}</SelectItem>
                </SelectContent>
              </Select>
              <span className="field-help">{t('edge.levelHint')}</span>
            </div>
            <div className="field-stack">
              <Label>{t('edge.minBytes')}</Label>
              <ByteUnitInput
                value={compressionForm.minBytes}
                minBytes={0}
                defaultUnit="KB"
                onChange={(minBytes) => {
                  const next = { ...compressionForm, minBytes };
                  setCompressionForm(next);
                  pushCompressionToDraft(next);
                }}
              />
              <span className="field-help">{t('edge.minBytesHint')}</span>
            </div>
            <div className="field-stack">
              <Label>{t('edge.types')}</Label>
              <Input
                placeholder="text/,application/json,application/javascript"
                value={compressionForm.types}
                onChange={(e) => {
                  const next = { ...compressionForm, types: e.target.value };
                  setCompressionForm(next);
                  pushCompressionToDraft(next);
                }}
              />
              <span className="field-help">{t('edge.typesHint')}</span>
            </div>
            <div className="form-action-row"><Button type="submit">{t('common.save')}</Button></div>
          </form>
        </section>
      </div>

      <section className="table-panel">
        <div className="panel-heading">
          <h2><ListPlus size={16} /> {t('edge.headers')}</h2>
          <div className="table-identity">
            <Button variant="outline" onClick={addHeader}><Plus size={14} />{t('common.add')}</Button>
            <Button onClick={saveDraft} loading={mutation.isPending}>{t('common.save')}</Button>
          </div>
        </div>
        {edge.headers.rules.length === 0 ? (
          <Empty description={t('common.noData')} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('rules.name')}</TableHead>
                <TableHead>{t('edge.operation')}</TableHead>
                <TableHead>{t('edge.header')}</TableHead>
                <TableHead>{t('edge.value')}</TableHead>
                <TableHead>{t('edge.paths')}</TableHead>
                <TableHead>{t('rules.enabled')}</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {edge.headers.rules.map((record, index) => (
                <TableRow key={record.id}>
                  <TableCell>
                    <Input value={record.name} onChange={(e) => updateHeader(index, { name: e.target.value })} />
                  </TableCell>
                  <TableCell>
                    <Select
                      value={record.operation}
                      onValueChange={(value) => updateHeader(index, { operation: value as HeaderRule['operation'] })}
                    >
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="set">{t('edge.operationSet')}</SelectItem>
                        <SelectItem value="add">{t('edge.operationAppend')}</SelectItem>
                        <SelectItem value="delete">{t('edge.operationRemove')}</SelectItem>
                      </SelectContent>
                    </Select>
                  </TableCell>
                  <TableCell>
                    <Input value={record.header} onChange={(e) => updateHeader(index, { header: e.target.value })} />
                  </TableCell>
                  <TableCell>
                    <Input
                      value={record.value}
                      disabled={record.operation === 'delete'}
                      onChange={(e) => updateHeader(index, { value: e.target.value })}
                    />
                  </TableCell>
                  <TableCell>
                    <Input
                      value={record.path_prefix}
                      placeholder="/api/"
                      onChange={(e) => updateHeader(index, { path_prefix: e.target.value })}
                    />
                  </TableCell>
                  <TableCell>
                    <Switch checked={record.enabled} onCheckedChange={(enabled) => updateHeader(index, { enabled })} />
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="destructive"
                      size="icon"
                      aria-label={t('common.delete')}
                      onClick={() => removeHeader(record.id)}
                    >
                      <Trash2 size={14} />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </section>
    </section>
  );
}

function split(value: unknown) {
  return String(value ?? '').split(',').map((item) => item.trim()).filter(Boolean);
}

function normalizeAlgorithms(value: string[]) {
  const out = (value ?? []).map((item) => (item === 'brotli' ? 'br' : item)).filter((item) => item === 'br' || item === 'gzip');
  return out.length > 0 ? Array.from(new Set(out)) : ['br', 'gzip'];
}

function normalizeCompressionLevel(level: number) {
  if (level <= 2) return 1;
  if (level <= 4) return 3;
  if (level <= 6) return 5;
  if (level <= 8) return 7;
  if (level >= 9) return 9;
  return 5;
}

function StatusCodeSelector({ value, onChange }: { value?: string[]; onChange?: (next: string[]) => void }) {
  const selected = Array.isArray(value) ? value : [];
  const toggle = (choice: string) => {
    const next = selected.includes(choice)
      ? selected.filter((item) => item !== choice)
      : [...selected, choice];
    onChange?.(next);
  };
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button type="button" variant="outline" className="w-full justify-start font-normal">
          {selected.length > 0 ? selected.join(', ') : '2xx, 3xx, 200, 304'}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-72 max-h-64 overflow-auto" align="start">
        <div className="flex flex-col gap-2">
          {statusCodeChoices.map((choice) => (
            <label key={choice} className="flex items-center gap-2 text-sm">
              <Checkbox checked={selected.includes(choice)} onCheckedChange={() => toggle(choice)} />
              {choice}
            </label>
          ))}
        </div>
      </PopoverContent>
    </Popover>
  );
}

function statusCodesToChoices(codes: number[] | undefined) {
  const values = new Set((codes ?? []).filter((code) => Number.isInteger(code) && code >= 100 && code <= 599));
  const out: string[] = [];
  for (const family of [2, 3, 4, 5]) {
    let complete = true;
    for (let code = family * 100; code < family * 100 + 100; code += 1) {
      if (!values.has(code)) {
        complete = false;
        break;
      }
    }
    if (complete) {
      out.push(`${family}xx`);
      for (let code = family * 100; code < family * 100 + 100; code += 1) {
        values.delete(code);
      }
    }
  }
  return [...out, ...Array.from(values).sort((a, b) => a - b).map(String)];
}

function parseStatusCodeChoices(value: unknown) {
  const parts = Array.isArray(value) ? value.map(String) : split(value);
  const codes = new Set<number>();
  for (const part of parts) {
    const normalized = part.trim().toLowerCase();
    const family = normalized.match(/^([2-5])xx$/);
    if (family) {
      const base = Number(family[1]) * 100;
      for (let code = base; code < base + 100; code += 1) {
        codes.add(code);
      }
      continue;
    }
    const code = Number(normalized);
    if (Number.isInteger(code) && code >= 100 && code <= 599) {
      codes.add(code);
    }
  }
  return Array.from(codes).sort((a, b) => a - b);
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
    <div className="compound-input flex gap-2">
      <Input
        type="number"
        min={1}
        value={parts.amount}
        onChange={(e) => emit(e.target.value)}
      />
      <Select
        value={unit}
        onValueChange={(next) => {
          const nextUnit = next as DurationUnit;
          setUnit(nextUnit);
          emit(parts.amount, nextUnit);
        }}
      >
        <SelectTrigger className="w-28"><SelectValue /></SelectTrigger>
        <SelectContent>
          <SelectItem value="d">{t('common.days')}</SelectItem>
          <SelectItem value="h">{t('common.hours')}</SelectItem>
          <SelectItem value="m">{t('common.minutes')}</SelectItem>
          <SelectItem value="s">{t('common.seconds')}</SelectItem>
        </SelectContent>
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
    <div className="compound-input flex gap-2">
      <Input
        type="number"
        min={0}
        step={parts.unit === 'MB' ? 0.01 : 1}
        value={parts.amount}
        onChange={(e) => emit(e.target.value)}
      />
      <Select
        value={unit}
        onValueChange={(next) => {
          const nextUnit = next as ByteUnit;
          setUnit(nextUnit);
          emit(parts.amount, nextUnit);
        }}
      >
        <SelectTrigger className="w-24"><SelectValue /></SelectTrigger>
        <SelectContent>
          <SelectItem value="KB">KB</SelectItem>
          <SelectItem value="MB">MB</SelectItem>
        </SelectContent>
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
  if (raw.endsWith('d')) return numeric * durationUnitToNanoseconds('d');
  if (raw.endsWith('h')) return numeric * durationUnitToNanoseconds('h');
  if (raw.endsWith('m')) return numeric * durationUnitToNanoseconds('m');
  if (raw.endsWith('s')) return numeric * durationUnitToNanoseconds('s');
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
