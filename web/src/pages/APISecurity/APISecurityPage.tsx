import { useState, type FormEvent } from 'react';
import { Badge, Button, Input, Label, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, toast } from '@/components/ui';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { ClipboardCheck, Radar, RotateCcw, Trash2 } from 'lucide-react';
import { fetchAPISecEndpoints, validateAPIRequest } from '../../api/client';
import QueryErrorState from '../../components/QueryErrorState';

export default function APISecurityPage() {
  const { t } = useTranslation();
  const [findings, setFindings] = useState<Array<Record<string, unknown>>>([]);
  const [hasValidated, setHasValidated] = useState(false);
  const [ignoredEndpoints, setIgnoredEndpoints] = useState<Set<string>>(new Set());
  const [method, setMethod] = useState('GET');
  const [path, setPath] = useState('/api/search');
  const [query, setQuery] = useState('');
  const [headers, setHeaders] = useState('');
  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['apisec'],
    queryFn: fetchAPISecEndpoints,
    retry: false,
  });
  const validateMutation = useMutation({
    mutationFn: validateAPIRequest,
    onSuccess: (result) => {
      setFindings(result.findings);
      setHasValidated(true);
    },
    onError: (error) => {
      toast.error(error.message || t('common.requestFailed'));
    },
  });
  const allEndpoints = data?.endpoints ?? [];
  const visibleEndpoints = allEndpoints.filter((ep) => !ignoredEndpoints.has(ep.method + ep.path));
  const ignoredList = allEndpoints.filter((ep) => ignoredEndpoints.has(ep.method + ep.path));

  function ignoreEndpoint(key: string) {
    setIgnoredEndpoints((prev) => new Set([...prev, key]));
  }

  function restoreEndpoint(key: string) {
    setIgnoredEndpoints((prev) => {
      const next = new Set(prev);
      next.delete(key);
      return next;
    });
  }

  function onValidate(event: FormEvent) {
    event.preventDefault();
    validateMutation.mutate({
      method,
      path,
      query,
      headers: parseHeaders(headers),
      content_length: 0,
    });
  }

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('apisec.title')}</h1>
          <p>{t('apisec.subtitle')}</p>
        </div>
      </header>
      <div className="api-security-grid">
        <section className="panel api-discovery-panel">
          <div className="panel-heading"><h2><Radar size={16} /> {t('apisec.discovery')}</h2></div>
          {isError && !data ? (
            <QueryErrorState onRetry={() => void refetch()} retrying={isFetching} />
          ) : (
            <>
              <div className="api-endpoints-table">
                {isLoading ? (
                  <div className="empty-state" role="status">{t('common.loading')}</div>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>{t('apisec.method')}</TableHead>
                        <TableHead>{t('apisec.path')}</TableHead>
                        <TableHead>{t('apisec.count')}</TableHead>
                        <TableHead>{t('apisec.blocked')}</TableHead>
                        <TableHead>{t('apisec.status')}</TableHead>
                        <TableHead />
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {visibleEndpoints.map((rec) => (
                        <TableRow key={rec.method + rec.path}>
                          <TableCell><Badge variant="secondary">{rec.method}</Badge></TableCell>
                          <TableCell><code className="table-code api-endpoint-path" title={rec.path}>{rec.path}</code></TableCell>
                          <TableCell>{rec.count}</TableCell>
                          <TableCell>
                            <Badge variant={rec.blocked > 0 ? 'destructive' : 'success'}>{rec.blocked}</Badge>
                          </TableCell>
                          <TableCell>
                            <span className="api-status-group">
                              {Object.entries(rec.status_family).map(([k, v]) => (
                                <Badge key={k} variant="outline">{k}: {v}</Badge>
                              ))}
                            </span>
                          </TableCell>
                          <TableCell>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => ignoreEndpoint(rec.method + rec.path)}
                            >
                              <Trash2 size={14} />
                              {t('common.ignore')}
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </div>
              <div className="api-endpoints-mobile">
                {visibleEndpoints.map((endpoint) => (
                  <article className="api-endpoint-card" key={endpoint.method + endpoint.path}>
                    <div className="api-endpoint-card-heading">
                      <Badge variant="secondary">{endpoint.method}</Badge>
                      <code title={endpoint.path}>{endpoint.path}</code>
                    </div>
                    <dl>
                      <div><dt>{t('apisec.count')}</dt><dd>{endpoint.count}</dd></div>
                      <div><dt>{t('apisec.blocked')}</dt><dd><Badge variant={endpoint.blocked > 0 ? 'destructive' : 'success'}>{endpoint.blocked}</Badge></dd></div>
                      <div><dt>{t('apisec.status')}</dt><dd className="api-status-group">{Object.entries(endpoint.status_family).map(([key, value]) => <Badge key={key} variant="outline">{key}: {value}</Badge>)}</dd></div>
                    </dl>
                    <Button size="sm" variant="outline" onClick={() => ignoreEndpoint(endpoint.method + endpoint.path)}>
                      <Trash2 size={14} />
                      {t('common.ignore')}
                    </Button>
                  </article>
                ))}
              </div>
              {ignoredList.length > 0 && (
                <div className="api-ignored-list" style={{ marginTop: 12, display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
                  <span style={{ fontSize: 13, opacity: 0.8 }}>{t('common.ignore')}: {ignoredList.length}</span>
                  {ignoredList.map((endpoint) => {
                    const key = endpoint.method + endpoint.path;
                    return (
                      <Button
                        key={key}
                        size="sm"
                        variant="outline"
                        title={`${endpoint.method} ${endpoint.path}`}
                        aria-label={`${t('common.reset')}: ${endpoint.method} ${endpoint.path}`}
                        onClick={() => restoreEndpoint(key)}
                      >
                        <RotateCcw size={12} />
                        {endpoint.method} · {t('common.reset')}
                      </Button>
                    );
                  })}
                  {ignoredList.length > 1 && (
                    <Button size="sm" variant="ghost" onClick={() => setIgnoredEndpoints(new Set())}>
                      {t('common.reset')}
                    </Button>
                  )}
                </div>
              )}
            </>
          )}
        </section>
        <section className="panel api-validation-panel">
          <div className="panel-heading"><h2><ClipboardCheck size={16} /> {t('apisec.validation')}</h2></div>
          <p className="field-help">{t('apisec.validationHint')}</p>
          <form className="space-y-3" onSubmit={onValidate}>
            <div className="space-y-1.5">
              <Label>{t('apisec.method')}</Label>
              <Select value={method} onValueChange={setMethod}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="GET">GET</SelectItem>
                  <SelectItem value="POST">POST</SelectItem>
                  <SelectItem value="PUT">PUT</SelectItem>
                  <SelectItem value="DELETE">DELETE</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label>{t('apisec.path')}</Label>
              <Input placeholder="/api/search" value={path} onChange={(e) => setPath(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label>{t('apisec.query')}</Label>
              <Input placeholder="q=test&page=1" value={query} onChange={(e) => setQuery(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label>{t('apisec.headers')}</Label>
              <Input placeholder="Content-Type: application/json" value={headers} onChange={(e) => setHeaders(e.target.value)} />
            </div>
            <Button type="submit" loading={validateMutation.isPending}>{t('apisec.validate')}</Button>
          </form>
          <div className="event-list api-findings">
            {!hasValidated
              ? null
              : findings.length === 0
                ? <Badge variant="success">{t('apisec.clean')}</Badge>
                : findings.map((f, i) => <Badge className="api-finding-tag" key={i} variant="warning">{String(f.message)}</Badge>)}
          </div>
        </section>
      </div>
    </section>
  );
}

function parseHeaders(value: string) {
  const headers: Record<string, string> = {};
  for (const line of String(value ?? '').split('\n')) {
    const colon = line.indexOf(':');
    if (colon > 0) headers[line.slice(0, colon).trim()] = line.slice(colon + 1).trim();
  }
  return headers;
}
