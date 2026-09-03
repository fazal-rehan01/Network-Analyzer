import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("Page crashed:", error, info);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="text-center py-16">
          <div className="text-rose-300 font-medium mb-2">Something went wrong on this page</div>
          <div className="text-sm text-slate-500 mb-4 max-w-md mx-auto break-words">
            {this.state.error.message}
          </div>
          <button
            onClick={() => {
              this.setState({ error: null });
              window.location.hash = "";
              window.location.reload();
            }}
            className="px-3 py-1.5 rounded-lg bg-slate-800 text-sm hover:bg-slate-700"
          >
            Reload application
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}