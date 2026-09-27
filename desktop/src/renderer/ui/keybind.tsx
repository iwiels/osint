/** Keybind - representación de un atajo de teclado (Enter, Ctrl+K, F12). */
import { cn } from "./lib/cn";
import "./keybind.css";

export interface KeybindProps {
  /** Teclas en orden de pulsación: ["Ctrl", "Shift", "I"]. */
  keys: string[];
  className?: string;
}

export function Keybind({ keys, className }: KeybindProps) {
  // Las teclas se pintan como cajas `<kbd>` sueltas: se ocultan al lector y el
  // atajo se ofrece como una sola cadena, porque un `aria-label` sobre un `span`
  // sin rol no se anuncia de forma fiable.
  return (
    <>
      <span data-component="keybind" className={cn(className)} aria-hidden="true">
        {keys.map((key) => (
          <kbd key={key} data-slot="keybind-key">
            {key}
          </kbd>
        ))}
      </span>
      <span className="sr-only">{keys.join(" + ")}</span>
    </>
  );
}
