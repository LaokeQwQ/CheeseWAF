import { Component, type ErrorInfo, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import BrandLogo from './BrandLogo';

type BoundaryTexts = {
  title: string;
  subtitle: string;
  traceLabel: string;
  reload: string;
  home: string;
};

type BoundaryProps = BoundaryTexts & {
  children: ReactNode;
  resetKey: string;
};

type BoundaryState = {
  error: Error | null;
  traceID: string;
};

class AppErrorBoundaryInner extends Component<BoundaryProps, BoundaryState> {
  state: BoundaryState = { error: null, traceID: '' };

  static getDerivedStateFromError(error: Error): BoundaryState {
    return { error, traceID: newUITraceID() };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[CheeseWAF UI error]', this.state.traceID, error, info.componentStack);
    reportUIError(this.state.traceID, error, info);
  }

  componentDidUpdate(prevProps: BoundaryProps) {
    if (prevProps.resetKey !== this.props.resetKey && this.state.error) {
      this.setState({ error: null, traceID: '' });
    }
  }

  render() {
    if (!this.state.error) {
      return this.props.children;
    }
    return (
      <section className="ui-error-boundary" role="alert">
        <div>
          <header className="ui-error-brand">
            <span className="ui-error-logo">
              <BrandLogo alt="CheeseWAF" />
            </span>
            <span>CheeseWAF</span>
          </header>
          <h1>{this.props.title}</h1>
          <p>{this.props.subtitle}</p>
          <div className="ui-error-trace">
            <span>{this.props.traceLabel}</span>
            <code>{this.state.traceID}</code>
          </div>
          <div className="ui-error-actions">
            <button type="button" onClick={() => window.location.reload()}>{this.props.reload}</button>
            <button type="button" onClick={() => { window.location.href = '/'; }}>{this.props.home}</button>
          </div>
        </div>
      </section>
    );
  }
}

export function AppErrorBoundary({ children, resetKey }: { children: ReactNode; resetKey: string }) {
  const { t } = useTranslation();
  return (
    <AppErrorBoundaryInner
      resetKey={resetKey}
      title={t('uiError.title')}
      subtitle={t('uiError.subtitle')}
      traceLabel={t('uiError.traceLabel')}
      reload={t('uiError.reload')}
      home={t('uiError.home')}
    >
      {children}
    </AppErrorBoundaryInner>
  );
}

function newUITraceID() {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return `cw-${Array.from(bytes, (item) => item.toString(16).padStart(2, '0')).join('')}`;
}

function reportUIError(traceID: string, error: Error, info: ErrorInfo) {
  const token = localStorage.getItem('cheesewaf-token');
  if (!token) {
    return;
  }
  const payload = {
    trace_id: traceID || newUITraceID(),
    name: error.name,
    message: error.message,
    stack: truncateForReport(error.stack ?? ''),
    component_stack: truncateForReport(info.componentStack),
    path: `${window.location.pathname}${window.location.search}${window.location.hash}`,
    user_agent: navigator.userAgent,
    language: navigator.language,
    viewport: {
      width: window.innerWidth,
      height: window.innerHeight,
    },
  };
  void fetch('/api/ui/errors', {
    method: 'POST',
    keepalive: true,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(payload),
  }).catch((reportError) => {
    console.error('[CheeseWAF UI error report failed]', payload.trace_id, reportError);
  });
}

function truncateForReport(value: string | null | undefined, max = 8_000) {
  if (!value) {
    return '';
  }
  return value.length > max ? `${value.slice(0, max)}...(truncated)` : value;
}
