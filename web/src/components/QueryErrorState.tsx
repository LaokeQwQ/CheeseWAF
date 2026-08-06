import { Button } from '../ui';
import { useTranslation } from 'react-i18next';

type Props = {
  title?: string;
  message?: string;
  onRetry?: () => void;
  retrying?: boolean;
  className?: string;
};

/** Shared query failure UI: distinguishes empty data from request failure. */
export default function QueryErrorState({ title, message, onRetry, retrying, className }: Props) {
  const { t } = useTranslation();
  return (
    <div className={className ? `query-error-state ${className}` : 'query-error-state'} role="alert">
      <div className="query-error-state__body">
        <strong>{title ?? t('common.loadFailed')}</strong>
        {message ? <span>{message}</span> : null}
      </div>
      {onRetry ? (
        <Button size="small" type="primary" loading={retrying} onClick={onRetry}>
          {t('common.retry')}
        </Button>
      ) : null}
    </div>
  );
}
