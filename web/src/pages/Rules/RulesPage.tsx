import { useMemo, useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Plus, ShieldCheck, Wand2 } from 'lucide-react';
import {
  Badge,
  Button,
  Dialog,
  DialogContent,
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
import { createRule, fetchRules } from '../../api/client';
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
  const [draft, setDraft] = useState<RuleDraft>(emptyDraft);
  const [testInput, setTestInput] = useState('');
  const [page, setPage] = useState(1);
  const { data, isError, isLoading, refetch } = useQuery({ queryKey: ['rules'], queryFn: () => fetchRules(), retry: false });
  const mutation = useMutation({
    mutationFn: createRule,
    onSuccess: () => {
      setOpen(false);
      setDraft(emptyDraft());
      setTestInput('');
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
    setDraft(emptyDraft());
    setTestInput('');
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
    mutation.mutate({
      site_id: 'default',
      name: draft.name,
      description: draft.description ?? '',
      pattern,
      location: draft.location ?? 'uri',
      action: draft.action ?? 'block',
      severity: draft.severity ?? 'medium',
      priority,
      enabled: true,
    });
  };

  return (
    <section className="page-surface rules-page">
      <header className="page-header">
        <div>
          <h1>{t('rules.wafTitle')}</h1>
          <p>{t('rules.subtitle')}</p>
        </div>
        <Button
          onClick={() => {
            setDraft(emptyDraft());
            setTestInput('');
            setOpen(true);
          }}
        >
          <Plus size={16} />
          {t('rules.create')}
        </Button>
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
                        disabled
                        aria-label={rule.enabled ? t('common.enabled') : t('common.disabled')}
                      />
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
        open={open}
        onOpenChange={(next) => {
          if (!next) closeModal();
          else setOpen(true);
        }}
      >
        <DialogContent className="rule-editor-modal max-w-4xl">
          <DialogHeader>
            <DialogTitle>{t('rules.create')}</DialogTitle>
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
    </section>
  );
}
