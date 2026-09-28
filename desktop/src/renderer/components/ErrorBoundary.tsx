/**
 * ErrorBoundary - frontera de error de React.
 *
 * Un throw dentro del canvas del grafo (ForceGraph2D/D3) o de cualquier panel
 * no debe tumbar la consola entera: la captura aquí mantiene el resto de la UI
 * viva y ofrece reiniciar el panel afectado remontándolo con otra `key`.
 */

import { Component, type ErrorInfo, type ReactNode } from "react";
import { cn } from "../ui";

interface ErrorBoundaryProps {
  /** Etiqueta humana del panel protegido (mensajes y consola del main). */
  label: string;
  /** Layout ancho: el fallback llena el panel en vez de una tarjeta pequeña. */
  fill?: boolean;
  children: ReactNode;
}

interface ErrorBoundaryState {
  error: Error | null;
}

export default class ErrorBoundary extends Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // El proceso main reenvía la consola del renderer a la terminal (diagnóstico).
    console.error(`[${this.props.label}] panel crash:`, error.message, info.componentStack);
  }

  private readonly reset = () => {
    this.setState({ error: null });
  };

  render(): ReactNode {
    const { error } = this.state;
    const { label, fill, children } = this.props;
    if (!error) return children;
    return (
      <div
        role="alert"
        className={cn(
          "flex flex-col items-center justify-center gap-3 border border-border-critical-base bg-surface-critical-weak p-6 text-center",
          fill && "min-h-0 flex-1",
        )}
      >
        <p className="text-[13px] font-medium text-text-critical">
          El panel {label} falló y quedó en pausa.
        </p>
        <p className="max-w-prose font-mono text-[11.5px] break-words text-text-weak">
          {error.message}
        </p>
        <button
          type="button"
          onClick={this.reset}
          className="rounded-xs border border-border-strong-base bg-surface-raised px-3 py-1.5 text-[12.5px] text-text-strong hover:bg-surface-hover"
        >
          Reintentar
        </button>
      </div>
    );
  }
}
