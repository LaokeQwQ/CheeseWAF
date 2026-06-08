import { Tag } from '@arco-design/web-react';
import { useTranslation } from 'react-i18next';
import type { AttackAnalysis } from '../types/api';

type Props = {
  analysis: AttackAnalysis;
};

export default function AIAnalysisMeta({ analysis }: Props) {
  const { t } = useTranslation();
  const provider = [analysis.provider, analysis.model].filter(Boolean).join(' / ');
  return (
    <div className="ai-analysis-meta">
      <Tag color={analysis.ai_used ? 'green' : 'blue'}>
        {analysis.ai_used ? t('ai.aiUsed') : t('ai.heuristicUsed')}
      </Tag>
      {provider && <span>{provider}</span>}
      {positive(analysis.output_tokens) && <span>{t('ai.outputTokens', { value: analysis.output_tokens })}</span>}
      {positive(analysis.total_tokens) && <span>{t('ai.totalTokens', { value: analysis.total_tokens })}</span>}
    </div>
  );
}

function positive(value?: number) {
  return Number.isFinite(value) && Number(value) > 0;
}
