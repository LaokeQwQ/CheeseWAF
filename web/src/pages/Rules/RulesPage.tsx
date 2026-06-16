import { Button, Form, Input, InputNumber, Message as ArcoMessage, Modal, Select, Switch, Table, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Plus, ShieldCheck, Wand2 } from 'lucide-react';
import { createRule, fetchRules } from '../../api/client';

type RuleTemplate = {
  key: string;
  label: string;
  pattern: string;
  description: string;
};

export default function RulesPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [patternDraft, setPatternDraft] = useState('');
  const [testInput, setTestInput] = useState('');
  const { data, isError, isLoading, refetch } = useQuery({ queryKey: ['rules'], queryFn: () => fetchRules(), retry: false });
  const mutation = useMutation({
    mutationFn: createRule,
    onSuccess: () => {
      setOpen(false);
      queryClient.invalidateQueries({ queryKey: ['rules'] });
    },
    onError: (error) => ArcoMessage.error(error.message),
  });
  const rows = data ?? [];
  const severityLabel = (severity: string) => {
    if (severity === 'low') return t('rules.low');
    if (severity === 'medium') return t('rules.medium');
    if (severity === 'high') return t('rules.high');
    if (severity === 'critical') return t('rules.critical');
    return severity;
  };
  const templates = ruleTemplates(t);
  const testResult = testPattern(patternDraft, testInput);
  const handleRuleSubmit = (values: Record<string, any>) => {
    const pattern = String(values.pattern || patternDraft || '').trim();
    const priority = Number(values.priority ?? 100);
    const validation = validateRuleDraft(pattern, priority, t);
    if (!validation.ok) {
      ArcoMessage.warning(validation.error);
      return;
    }
    mutation.mutate({
      site_id: values.site_id ?? 'default',
      name: values.name,
      description: values.description ?? '',
      pattern,
      location: values.location ?? 'uri',
      action: values.action ?? 'block',
      severity: values.severity ?? 'medium',
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
        <Button type="primary" icon={<Plus size={16} />} onClick={() => {
          setPatternDraft('');
          setTestInput('');
          setOpen(true);
        }}>
          {t('rules.create')}
        </Button>
      </header>

      <section className="table-panel">
        {isError && (
          <div className="inline-error">
            <span>{t('rules.loadFailed')}</span>
            <Button size="small" onClick={() => refetch()}>{t('common.retry')}</Button>
          </div>
        )}
        <Table
          rowKey="id"
          pagination={{ pageSize: 8 }}
          loading={isLoading}
          data={rows}
          columns={[
            {
              title: t('rules.name'),
              dataIndex: 'name',
              render: (name: string) => (
                <span className="table-identity">
                  <ShieldCheck size={17} />
                  {name}
                </span>
              ),
            },
            { title: t('rules.pattern'), dataIndex: 'pattern', render: (pattern: string) => <code className="table-code" title={pattern}>{pattern}</code> },
            { title: t('rules.location'), dataIndex: 'location' },
            {
              title: t('rules.severity'),
              dataIndex: 'severity',
              render: (severity: string) => (
                <span className="status-group">
                  <Tag color={severity === 'critical' ? 'red' : severity === 'high' ? 'orange' : 'blue'}>{severityLabel(severity)}</Tag>
                </span>
              ),
            },
            { title: t('rules.priority'), dataIndex: 'priority' },
            { title: t('rules.enabled'), dataIndex: 'enabled', render: (enabled: boolean) => <Switch checked={enabled} size="small" /> },
          ]}
        />
      </section>

      <Modal className="rule-editor-modal" title={t('rules.create')} visible={open} onCancel={() => setOpen(false)} footer={null}>
        <Form
          layout="vertical"
          className="rule-editor-form"
          onSubmit={handleRuleSubmit}
        >
          <div className="rule-editor-grid">
            <section className="rule-editor-section">
              <h2>{t('rules.basicInfo')}</h2>
              <Form.Item label={t('rules.name')} field="name" required extra={t('rules.nameHint')}><Input placeholder={t('rules.namePlaceholder')} /></Form.Item>
              <Form.Item label={t('rules.description')} field="description" extra={t('rules.descriptionHint')}><Input.TextArea autoSize={{ minRows: 2, maxRows: 4 }} /></Form.Item>
            </section>

            <section className="rule-editor-section">
              <h2>{t('rules.matchCondition')}</h2>
              <Form.Item label={t('rules.pattern')} field="pattern" required extra={t('rules.patternHint')}>
                <Input.TextArea
                  value={patternDraft}
                  autoSize={{ minRows: 4, maxRows: 8 }}
                  placeholder={t('rules.patternPlaceholder')}
                  onChange={setPatternDraft}
                />
              </Form.Item>
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
                      onClick={() => setPatternDraft(template.pattern)}
                      title={template.description}
                    >
                      {template.label}
                    </button>
                  ))}
                </div>
              </div>
              <label className="rule-test-box">
                <span>{t('rules.testInput')}</span>
                <Input.TextArea value={testInput} autoSize={{ minRows: 3, maxRows: 6 }} placeholder={t('rules.testInputPlaceholder')} onChange={setTestInput} />
                <Tag color={testResult.ok ? (testResult.matched ? 'red' : 'green') : 'orange'}>
                  {testResult.ok ? (testResult.matched ? t('rules.testMatched') : t('rules.testNotMatched')) : testResult.error}
                </Tag>
              </label>
            </section>

            <section className="rule-editor-section">
              <h2>{t('rules.actionAndPriority')}</h2>
              <Form.Item label={t('rules.location')} field="location" extra={t('rules.locationHint')}>
                <Select defaultValue="uri">
                  <Select.Option value="uri">URI</Select.Option>
                  <Select.Option value="header">Header</Select.Option>
                  <Select.Option value="query">Query</Select.Option>
                  <Select.Option value="body">Body</Select.Option>
                  <Select.Option value="cookie">Cookie</Select.Option>
                </Select>
              </Form.Item>
              <Form.Item label={t('logs.action')} field="action" extra={t('rules.actionHint')}>
                <Select defaultValue="block">
                  <Select.Option value="block">{t('common.block')}</Select.Option>
                  <Select.Option value="challenge">{t('logs.challenge')}</Select.Option>
                  <Select.Option value="log">{t('logs.log')}</Select.Option>
                </Select>
              </Form.Item>
              <Form.Item label={t('rules.severity')} field="severity" extra={t('rules.severityHint')}>
                <Select defaultValue="medium">
                  <Select.Option value="low">{t('rules.low')}</Select.Option>
                  <Select.Option value="medium">{t('rules.medium')}</Select.Option>
                  <Select.Option value="high">{t('rules.high')}</Select.Option>
                  <Select.Option value="critical">{t('rules.critical')}</Select.Option>
                </Select>
              </Form.Item>
              <Form.Item label={`${t('rules.priority')} (${t('rules.priorityHint')})`} field="priority" extra={t('rules.priorityHelp')}><InputNumber defaultValue={100} min={1} max={999} /></Form.Item>
            </section>
          </div>
          <div className="form-action-row">
            <Button onClick={() => setOpen(false)}>{t('common.cancel')}</Button>
            <Button type="primary" htmlType="submit" loading={mutation.isPending}>{t('common.save')}</Button>
          </div>
        </Form>
      </Modal>
    </section>
  );
}

function ruleTemplates(t: (key: string, options?: Record<string, unknown>) => string): RuleTemplate[] {
  return [
    { key: 'path-admin', label: t('rules.templatePathPrefix'), pattern: '^/admin(?:/|$)', description: t('rules.templatePathPrefixHint') },
    { key: 'sql-union', label: t('rules.templateSQLi'), pattern: '(?i)(?:union\\s+select|select\\s+.+\\s+from|sleep\\s*\\()', description: t('rules.templateSQLiHint') },
    { key: 'xss-script', label: t('rules.templateXSS'), pattern: '(?i)<\\s*script|javascript:|onerror\\s*=', description: t('rules.templateXSSHint') },
    { key: 'lfi', label: t('rules.templateLFI'), pattern: '(?:\\.\\./|\\.\\.\\\\|/etc/passwd|boot\\.ini)', description: t('rules.templateLFIHint') },
    { key: 'rce', label: t('rules.templateRCE'), pattern: '(?i)(?:;|\\||&&)\\s*(?:cat|curl|wget|bash|sh|powershell)\\b', description: t('rules.templateRCEHint') },
    { key: 'json-field', label: t('rules.templateJSONField'), pattern: '\"(?:role|is_admin|permission)\"\\s*:', description: t('rules.templateJSONFieldHint') },
  ];
}

function testPattern(pattern: string, input: string): { ok: true; matched: boolean } | { ok: false; error: string } {
  if (!pattern.trim() || !input.trim()) {
    return { ok: true, matched: false };
  }
  try {
    return { ok: true, matched: compileRulePattern(pattern).test(input) };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : 'Invalid expression' };
  }
}

function validateRuleDraft(pattern: string, priority: number, t: (key: string, options?: Record<string, unknown>) => string): { ok: true } | { ok: false; error: string } {
  if (!pattern.trim()) {
    return { ok: false, error: t('rules.patternRequired') };
  }
  if (!Number.isFinite(priority) || priority < 1 || priority > 999) {
    return { ok: false, error: t('rules.priorityInvalid') };
  }
  try {
    compileRulePattern(pattern);
  } catch (error) {
    const message = error instanceof Error ? error.message : t('rules.patternInvalid');
    return { ok: false, error: t('rules.patternInvalidWithReason', { reason: message }) };
  }
  if (isDangerouslyBroadPattern(pattern)) {
    return { ok: false, error: t('rules.patternTooBroad') };
  }
  return { ok: true };
}

function compileRulePattern(pattern: string) {
  const trimmed = pattern.trim();
  const inlineFlags = /^\(\?([imsu]+)\)/i.exec(trimmed);
  if (!inlineFlags) {
    return new RegExp(trimmed);
  }
  const flags = Array.from(new Set(inlineFlags[1].toLowerCase().split(''))).join('');
  return new RegExp(trimmed.slice(inlineFlags[0].length), flags);
}

function isDangerouslyBroadPattern(pattern: string) {
  const normalized = pattern
    .trim()
    .replace(/^\(\?[imsu]+\)/i, '')
    .replace(/\s+/g, '');
  return normalized === '' || ['.*', '.+', '^.*$', '^.+$', '.*?', '^.*?$', '[\\s\\S]*', '^[\\s\\S]*$'].includes(normalized);
}
