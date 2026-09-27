/** Spinner - indicador de actividad (motor arrancando, herramientas en curso). */
import { cn } from "./lib/cn";
import "./spinner.css";

export interface SpinnerProps {
  size?: "small" | "normal" | "large";
  /** Texto para lectores de pantalla; visualmente es sólo el aro. */
  label?: string;
  className?: string;
}

export function Spinner({ size = "normal", label = "Cargando", className }: SpinnerProps) {
  return (
    <span
      data-component="spinner"
      data-size={size}
      className={cn(className)}
      role="status"
      aria-label={label}
    />
  );
}
