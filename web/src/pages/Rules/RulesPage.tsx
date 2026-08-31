import { useMemo, useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Download, Edit3, Plus, ShieldCheck, Trash2, Upload, Wand2 } from 'lucide-react';
import {
  Badge,
  Button,
  ConfirmDialog,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  Label,
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
  Textarea,
  toast,
} from '@/components/ui';
import { createRule, deleteRule, exportCustomRules, fetchRules, fetchRulesExample, fetchSites, importCustomRules, updateRule } from '../../api/client';
import type { Rule } from '../../types/api';
import { ruleTemplates, testPattern, validateRuleDraft } from './rulesLogic';
import './RulesPage.css';

type RuleDraft = {
  name: string;
  description: string;
  pattern: string;
  location: string;
  action: string;
  severity: string;
  priority: number;
};

const emptyDraft = (): RuleDraft => ({
  name: '',
  description: '',
  pattern: '',
  location: 'uri',
  action: 'block',
  severity: 'medium',
  priority: 100,
});

const PAGE_SIZE = 8;

export default function RulesPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [importFile, setImportFile] = useState<File | null>(null);
  const [siteId, setSiteId] = useState('');
  const [draft, setDraft] = useState<RuleDraft>(emptyDraft);
  const [editingRule, setEditingRule] = useState<Rule | null>(null);
  const [testInput, setTestInput] = useState('');
  const [page, setPage] = useState(1);
  const [rulePendingDelete, setRulePendingDelete] = useState<Rule | null>(null);
  const sitesQuery = useQuery({ queryKey: ['sites'], queryFn: fetchSites, retry: false });
  const sites = sitesQuery.data ?? [];
  const selectedSiteId = siteId || sites[0]?.id || '';
  const { data, isError, isLoading, refetch } = useQuery({
    queryKey: ['rules', selectedSiteId],
    queryFn: () => fetchRules(selectedSiteId || undefined),
    retry: false,
    enabled: !sitesQuery.isPending,
  });
  const mutation = useMutation({
    mutationFn: (payload: Partial<Rule>) => editingRule ? updateRule(editingRule.id, payload) : createRule(payload),
    onSuccess: () => {
      setOpen(false);
      setEditingRule(null);
      setDraft(emptyDraft());
      setTestInput('');
      queryClient.invalidateQueries({ queryKey: ['rules'] });
    },
    onError: (error) => toast.error(error.message),
  });
  const deleteMutation = useMutation({
    mutationFn: (rule: Rule) => deleteRule(rule.id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['rules'] }),
    onError: (error) => toast.error(error.message),
  });
  const importMutation = useMutation({
    mutationFn: ({ id, body, contentType }: { id: string; body: string; contentType: string }) => importCustomRules(id, body, contentType),
    onSuccess: (result) => {
      setImportOpen(false);
      setImportFile(null);
      queryClient.invalidateQueries({ queryKey: ['rules'] });
      queryClient.invalidateQueries({ queryKey: ['sites'] });
      toast.success(t('rules.imported', { count: result.count }));
    },
    onError: (error) => toast.error(error.message),
  });
  const toggleMutation = useMutation({
    mutationFn: ({ rule, enabled }: { rule: Rule; enabled: boolean }) => updateRule(rule.id, { ...rule, enabled, site_id: rule.site_id || selectedSiteId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] });
    },
    onError: (error) => toast.error(error.message),
  });
  const rows = data ?? [];
  const totalPages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const pageRows = useMemo(() => {
    const start = (page - 1) * PAGE_SIZE;
    return rows.slice(start, start + PAGE_SIZE);
  }, [page, rows]);
  const severityLabel = (severity: string) => {
    if (severity === 'low') return t('rules.low');
    if (severity === 'medium') return t('rules.medium');
    if (severity === 'high') return t('rules.high');
    if (severity === 'critical') return t('rules.critical');
    return severity;
  };
  const severityVariant = (severity: string): 'destructive' | 'warning' | 'default' | 'secondary' => {
    if (severity === 'critical') return 'destructive';
    if (severity === 'high') return 'warning';
    if (severity === 'medium') return 'default';
    return 'secondary';
  };
  const templates = ruleTemplates(t);
  const testResult = testPattern(draft.pattern, testInput);
  const applyPattern = (pattern: string) => {
    setDraft((current) => ({ ...current, pattern }));
  };
  const closeModal = () => {
    if (mutation.isPending) return;
    setOpen(false);
    setEditingRule(null);
    setDraft(emptyDraft());
    setTestInput('');
  };
  const openEditor = (rule?: Rule) => {
    setEditingRule(rule ?? null);
    setDraft(rule ? {
      name: rule.name,
      description: rule.description ?? '',
      pattern: rule.pattern,
      location: rule.location,
      action: rule.action,
      severity: rule.severity,
      priority: rule.priority,
    } : emptyDraft());
    setTestInput('');
    setOpen(true);
  };
  const handleRuleSubmit = (event: FormEvent) => {
    event.preventDefault();
    const pattern = draft.pattern.trim();
    const priority = Number(draft.priority ?? 100);
    const validation = validateRuleDraft(pattern, priority, t);
    if (!validation.ok) {
      toast.warning(validation.error);
      return;
    }
    if (!selectedSiteId) {
      toast.warning(t('rules.importNeedSite'));
      return;
    }
    mutation.mutate({
      site_id: selectedSiteId,
      name: draft.name,
      description: draft.description ?? '',
      pattern,
      location: draft.location ?? 'uri',
      action: draft.action ?? 'block',
      severity: draft.severity ?? 'medium',
      priority,
      enabled: editingRule?.enabled ?? true,
    });
  };
  const saveBlob = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  };
  const downloadExample = async (format: 'yaml' | 'json') => {
    try {
      const blob = await fetchRulesExample(format);
      saveBlob(blob, `custom_rules.example.${format === 'json' ? 'json' : 'yaml'}`);
      toast.success(t('rules.exampleDownloaded'));
    } catch (error) {
      toast.error(error instanceof Error ? error.message : t('rules.loadFailed'));
    }
  };
  const downloadExport = async () => {
    if (!selectedSiteId) {
      toast.warning(t('rules.importNeedSite'));
      return;
    }
    try {
      const blob = await exportCustomRules(selectedSiteId, 'yaml');
      saveBlob(blob, `custom_rules-${selectedSiteId}.yaml`);
      toast.success(t('rules.exported'));
    } catch (error) {
      toast.error(error instanceof Error ? error.message : t('rules.loadFailed'));
    }
  };
  const handleImportSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!selectedSiteId) {
      toast.warning(t('rules.importNeedSite'));
      return;
    }
    if (!importFile) {
      toast.warning(t('rules.importNeedFile'));
      return;
    }
    const body = await importFile.text();
    const contentType = importFile.name.toLowerCase().endsWith('.json') ? 'application/json' : 'application/yaml';
    importMutation.mutate({ id: selectedSiteId, body, contentType });
  };

  return (
    <section className="page-surface rules-page">
      <header className="page-header">
        <div>
          <h1>{t('rules.wafTitle')}</h1>
          <p>{t('rules.subtitle')}</p>
        </div>
        <div className="rules-toolbar">
          <label className="rules-site-picker">
            <span>{t('rules.site')}</span>
            {selectedSiteId ? (
              <Select value={selectedSiteId} onValueChange={(value) => { setSiteId(value); setPage(1); }}>
                <SelectTrigger><SelectValue placeholder={t('rules.site')} /></SelectTrigger>
                <SelectContent>
                  {sites.map((site) => (
                    <SelectItem key={site.id} value={site.id}>{site.name || site.id}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            ) : (
              <Input disabled placeholder={t('rules.site')} />
            )}
            <em>{t('rules.siteHint')}</em>
          </label>
          <Button variant="outline" onClick={() => void downloadExport()} disabled={!selectedSiteId}>
            <Download size={16} />
            {t('rules.export')}
          </Button>
          <Button variant="outline" onClick={() => { setImportFile(null); setImportOpen(true); }} disabled={!selectedSiteId}>
            <Upload size={16} />
            {t('rules.import')}
          </Button>
          <Button
            onClick={() => openEditor()}
          >
            <Plus size={16} />
            {t('rules.create')}
          </Button>
        </div>
      </header>

      <section className="table-panel">
        {isError && (
          <div className="inline-error">
            <span>{t('rules.loadFailed')}</span>
            <Button size="sm" variant="outline" onClick={() => refetch()}>{t('common.retry')}</Button>
          </div>
        )}
        {isLoading ? (
          <div className="skeleton-list" role="status">{t('common.loading')}</div>
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('rules.name')}</TableHead>
                  <TableHead>{t('rules.pattern')}</TableHead>
                  <TableHead>{t('rules.location')}</TableHead>
                  <TableHead>{t('rules.severity')}</TableHead>
                  <TableHead>{t('rules.priority')}</TableHead>
                  <TableHead>{t('rules.enabled')}</TableHead>
                  <TableHead>{t('common.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pageRows.map((rule) => (
                  <TableRow key={rule.id}>
                    <TableCell>
                      <span className="table-identity">
                        <ShieldCheck size={17} />
                        {rule.name}
                      </span>
                    </TableCell>
                    <TableCell>
                      <code className="table-code" title={rule.pattern}>{rule.pattern}</code>
                    </TableCell>
                    <TableCell>{rule.location}</TableCell>
                    <TableCell>
                      <span className="status-group">
                        <Badge variant={severityVariant(rule.severity)}>{severityLabel(rule.severity)}</Badge>
                      </span>
                    </TableCell>
                    <TableCell>{rule.priority}</TableCell>
                    <TableCell>
                      <Switch
                        checked={rule.enabled}
                        disabled={toggleMutation.isPending}
                        onCheckedChange={(enabled) => toggleMutation.mutate({ rule, enabled })}
                        aria-label={rule.enabled ? t('common.enabled') : t('common.disabled')}
                      />
                    </TableCell>
                    <TableCell>
                      <div className="form-action-row">
                        <Button size="sm" variant="outline" onClick={() => openEditor(rule)} aria-label={`${t('common.edit')} ${rule.name}`}>
                          <Edit3 size={14} />
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => setRulePendingDelete(rule)} disabled={deleteMutation.isPending} aria-label={`${t('common.delete')} ${rule.name}`}>
                          <Trash2 size={14} />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {rows.length > PAGE_SIZE && (
              <div className="form-action-row" style={{ marginTop: 12 }}>
                <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>
                  ‹
                </Button>
                <span>{page} / {totalPages}</span>
                <Button size="sm" variant="outline" disabled={page >= totalPages} onClick={() => setPage((p) => Math.min(totalPages, p + 1))}>
                  ›
                </Button>
              </div>
            )}
          </>
        )}
      </section>

      <Dialog
        open={importOpen}
        onOpenChange={(next) => {
          if (importMutation.isPending) return;
          setImportOpen(next);
          if (!next) setImportFile(null);
        }}
      >
        <DialogContent className="rule-import-modal max-w-lg">
          <DialogHeader>
            <DialogTitle>{t('rules.importTitle')}</DialogTitle>
            <DialogDescription>{t('rules.importHint')}</DialogDescription>
          </DialogHeader>
          <form className="rule-import-form" onSubmit={(event) => { void handleImportSubmit(event); }}>
            <div className="rule-import-examples">
              <Button type="button" variant="outline" onClick={() => void downloadExample('yaml')}>
                <Download size={15} />
                {t('rules.downloadExampleYaml')}
              </Button>
              <Button type="button" variant="outline" onClick={() => void downloadExample('json')}>
                <Download size={15} />
                {t('rules.downloadExampleJson')}
              </Button>
            </div>
            <div className="field-stack">
              <Label htmlFor="custom-rules-file">{t('rules.importFile')}</Label>
              <Input
                id="custom-rules-file"
                type="file"
                accept=".yaml,.yml,.json,application/json,text/yaml"
                onChange={(event) => setImportFile(event.target.files?.[0] ?? null)}
              />
            </div>
            <DialogFooter className="form-action-row">
              <Button type="button" variant="outline" onClick={() => setImportOpen(false)} disabled={importMutation.isPending}>
                {t('common.cancel')}
              </Button>
              <Button type="submit" loading={importMutation.isPending}>{t('rules.importConfirm')}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      <Dialog
        open={open}
        onOpenChange={(next) => {
          if (!next) closeModal();
          else setOpen(true);
        }}
      >
        <DialogContent className="rule-editor-modal max-w-4xl">
          <DialogHeader>
            <DialogTitle>{t(editingRule ? 'common.edit' : 'rules.create')}</DialogTitle>
          </DialogHeader>
          <form className="rule-editor-form" noValidate onSubmit={handleRuleSubmit}>
            <div className="rule-editor-grid">
              <section className="rule-editor-section">
                <h2>{t('rules.basicInfo')}</h2>
                <div className="field-stack">
                  <Label htmlFor="rule-name">{t('rules.name')}</Label>
                  <Input
                    id="rule-name"
                    placeholder={t('rules.namePlaceholder')}
                    value={draft.name}
                    onChange={(e) => setDraft((c) => ({ ...c, name: e.target.value }))}
                    required
                  />
                  <span className="field-help">{t('rules.nameHint')}</span>
                </div>
                <div className="field-stack">
                  <Label htmlFor="rule-description">{t('rules.description')}</Label>
                  <Textarea
                    id="rule-description"
                    value={draft.description}
                    onChange={(e) => setDraft((c) => ({ ...c, description: e.target.value }))}
                    rows={3}
                  />
                  <span className="field-help">{t('rules.descriptionHint')}</span>
                </div>
              </section>

              <section className="rule-editor-section">
                <h2>{t('rules.matchCondition')}</h2>
                <div className="field-stack">
                  <Label htmlFor="rule-pattern">{t('rules.pattern')}</Label>
                  <Textarea
                    id="rule-pattern"
                    rows={5}
                    placeholder={t('rules.patternPlaceholder')}
                    value={draft.pattern}
                    onChange={(e) => setDraft((c) => ({ ...c, pattern: e.target.value }))}
                  />
                  <span className="field-help">{t('rules.patternHint')}</span>
                </div>
                <div className="rule-template-panel">
                  <div>
                    <strong><Wand2 size={14} /> {t('rules.expressionGenerator')}</strong>
                    <span>{t('rules.expressionGeneratorHint')}</span>
                  </div>
                  <div className="rule-template-list">
                    {templates.map((template) => (
                      <button
                        type="button"
                        key={template.key}
                        onClick={() => applyPattern(template.pattern)}
                        title={template.description}
                      >
                        {template.label}
                      </button>
                    ))}
                  </div>
                </div>
                <label className="rule-test-box">
                  <span>{t('rules.testInput')}</span>
                  <Textarea
                    value={testInput}
                    rows={3}
                    placeholder={t('rules.testInputPlaceholder')}
                    onChange={(e) => setTestInput(e.target.value)}
                  />
                  <Badge variant={testResult.ok ? (testResult.matched ? 'destructive' : 'success') : 'warning'}>
                    {testResult.ok ? (testResult.matched ? t('rules.testMatched') : t('rules.testNotMatched')) : testResult.error}
                  </Badge>
                </label>
              </section>

              <section className="rule-editor-section">
                <h2>{t('rules.actionAndPriority')}</h2>
                <div className="field-stack">
                  <Label>{t('rules.location')}</Label>
                  <Select value={draft.location} onValueChange={(location) => setDraft((c) => ({ ...c, location }))}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="uri">{t('rules.locationURI')}</SelectItem>
                      <SelectItem value="header">{t('rules.locationHeader')}</SelectItem>
                      <SelectItem value="query">{t('rules.locationQuery')}</SelectItem>
                      <SelectItem value="body">{t('rules.locationBody')}</SelectItem>
                      <SelectItem value="cookie">{t('rules.locationCookie')}</SelectItem>
                    </SelectContent>
                  </Select>
                  <span className="field-help">{t('rules.locationHint')}</span>
                </div>
                <div className="field-stack">
                  <Label>{t('logs.action')}</Label>
                  <Select value={draft.action} onValueChange={(action) => setDraft((c) => ({ ...c, action }))}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="block">{t('common.block')}</SelectItem>
                      <SelectItem value="challenge">{t('logs.challenge')}</SelectItem>
                      <SelectItem value="log">{t('logs.log')}</SelectItem>
                    </SelectContent>
                  </Select>
                  <span className="field-help">{t('rules.actionHint')}</span>
                </div>
                <div className="field-stack">
                  <Label>{t('rules.severity')}</Label>
                  <Select value={draft.severity} onValueChange={(severity) => setDraft((c) => ({ ...c, severity }))}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="low">{t('rules.low')}</SelectItem>
                      <SelectItem value="medium">{t('rules.medium')}</SelectItem>
                      <SelectItem value="high">{t('rules.high')}</SelectItem>
                      <SelectItem value="critical">{t('rules.critical')}</SelectItem>
                    </SelectContent>
                  </Select>
                  <span className="field-help">{t('rules.severityHint')}</span>
                </div>
                <div className="field-stack">
                  <Label htmlFor="rule-priority">{`${t('rules.priority')} (${t('rules.priorityHint')})`}</Label>
                  <Input
                    id="rule-priority"
                    type="number"
                    min={1}
                    max={999}
                    value={draft.priority}
                    onChange={(e) => setDraft((c) => ({ ...c, priority: Number(e.target.value || 100) }))}
                  />
                  <span className="field-help">{t('rules.priorityHelp')}</span>
                </div>
              </section>
            </div>
            <DialogFooter className="form-action-row">
              <Button type="button" variant="outline" onClick={closeModal} disabled={mutation.isPending}>{t('common.cancel')}</Button>
              <Button type="submit" loading={mutation.isPending}>{t('common.save')}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={rulePendingDelete !== null}
        onOpenChange={(next) => { if (!next) setRulePendingDelete(null); }}
        title={t('common.confirmDeleteTitle')}
        description={t('common.confirmDeleteEntry')}
        confirmLabel={t('common.delete')}
        loading={deleteMutation.isPending}
        onConfirm={() => {
          if (rulePendingDelete) {
            deleteMutation.mutate(rulePendingDelete);
          }
          setRulePendingDelete(null);
        }}
      />
    </section>
  );
}
