import React from 'react';

interface Props {
  children: React.ReactNode;
}

interface State {
  hasError: boolean;
  message: string;
}

export class ErrorBoundary extends React.Component<Props, State> {
  state: State = { hasError: false, message: '' };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, message: error?.message || 'Unexpected UI error' };
  }

  componentDidCatch(error: Error) {
    // Keep console visibility for demos without shipping a telemetry SDK.
    // eslint-disable-next-line no-console
    console.error('SentinelGW UI ErrorBoundary caught:', error);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-[40vh] flex items-center justify-center p-6">
          <div className="max-w-lg w-full rounded-xl border border-rose-500/40 bg-rose-950/40 p-5 text-center space-y-3">
            <h2 className="text-lg font-semibold text-rose-200">Something went wrong</h2>
            <p className="text-sm text-rose-100/80">{this.state.message}</p>
            <button
              type="button"
              className="px-4 py-2 rounded-lg bg-rose-500/20 border border-rose-400/40 text-rose-100 text-sm font-medium"
              onClick={() => {
                this.setState({ hasError: false, message: '' });
                window.location.reload();
              }}
            >
              Reload page
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
