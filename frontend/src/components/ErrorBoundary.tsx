import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  failed: boolean;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = { failed: false };

  public static getDerivedStateFromError(): State {
    return { failed: true };
  }

  public componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("RIFT UI error", {
      name: error.name,
      componentStack: info.componentStack,
    });
  }

  public render(): ReactNode {
    if (this.state.failed) {
      return (
        <main>
          <h1>RIFT could not load</h1>
          <p>Reload the page or contact the operator.</p>
        </main>
      );
    }
    return this.props.children;
  }
}
