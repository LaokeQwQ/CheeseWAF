import { Component, type ErrorInfo, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';

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
          <span className="ui-error-kicker">CheeseWAF</span>
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
  return `cw-ui-${Array.from(bytes, (item) => item.toString(16).padStart(2, '0')).join('')}`;
}
