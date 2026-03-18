import { Component, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  componentStack: string | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null, componentStack: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, componentStack: null };
  }

  componentDidCatch(error: Error, info: { componentStack: string }) {
    console.error("[AegisAI360] Render error caught by boundary:", error);
    console.error("[AegisAI360] Component stack:", info.componentStack);
    this.setState({ componentStack: info.componentStack });
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex items-center justify-center min-h-screen bg-background p-8">
          <div className="max-w-xl w-full space-y-4">
            <div className="flex items-center gap-3 mb-2">
              <div className="w-10 h-10 rounded-full bg-red-500/10 flex items-center justify-center">
                <svg className="w-5 h-5 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
                </svg>
              </div>
              <div>
                <h1 className="text-base font-semibold text-foreground">Platform Error</h1>
                <p className="text-xs text-muted-foreground">AegisAI360 encountered an unexpected error</p>
              </div>
            </div>

            <div className="rounded-md border border-red-500/30 bg-red-500/5 p-4 space-y-2">
              <p className="text-sm font-mono text-red-400 break-all">
                {this.state.error?.message || "Unknown error"}
              </p>
            </div>

            {this.state.componentStack && (
              <details className="text-xs text-muted-foreground">
                <summary className="cursor-pointer hover:text-foreground">Component trace</summary>
                <pre className="mt-2 p-3 rounded bg-muted/40 text-[10px] overflow-auto max-h-48 whitespace-pre-wrap break-all">
                  {this.state.componentStack}
                </pre>
              </details>
            )}

            <button
              className="w-full py-2 px-4 rounded-md bg-primary text-primary-foreground text-sm font-medium hover:opacity-90 transition-opacity"
              onClick={() => {
                this.setState({ hasError: false, error: null, componentStack: null });
                window.location.href = "/";
              }}
            >
              Reload Platform
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
