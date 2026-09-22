import { Component } from "react";
import type { ErrorInfo, ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

// Catches an uncaught render error anywhere in the routed page below it and
// shows a small recoverable panel instead of letting React unmount the whole
// tree to a blank white screen. This does not fix the underlying bug -- it
// contains the blast radius of one. AppShell keys this by the current route
// so navigating away and back always remounts with a clean state.
export class RouteErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("Route render error:", error, info.componentStack);
  }

  private handleRetry = (): void => {
    this.setState({ error: null });
  };

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div role="alert" className="rounded-lg border border-danger/40 bg-danger/10 p-5 text-sm text-danger">
        <div className="text-base font-black">Something went wrong loading this page.</div>
        <p className="mt-2 opacity-90">{error.message || "An unexpected error occurred while rendering this page."}</p>
        <div className="mt-4 flex flex-wrap gap-2">
          <button type="button" className="btn-secondary" onClick={this.handleRetry}>
            Try again
          </button>
          <button type="button" className="btn-secondary" onClick={() => window.location.reload()}>
            Reload page
          </button>
        </div>
      </div>
    );
  }
}
