/**
 * DockSurface - contenedor anclado sobre el compositor de la consola.
 * Portado de `components/dock-surface.css` de opencode: en vez de un diálogo
 * modal que tapa el caso, el aviso (permiso, pregunta, plan) aparece pegado al
 * campo de entrada y el analista sigue viendo el grafo y la traza.
 */

import type { ReactNode } from "react";
import { cn } from "./lib/cn";
import "./dock-surface.css";

export interface DockSurfaceProps {
  children: ReactNode;
  /** "shell" = superficie principal con sombra; "tray" = banda inferior pegada. */
  variant?: "shell" | "tray";
  className?: string;
}

export function DockSurface({ children, variant = "shell", className }: DockSurfaceProps) {
  return (
    <div data-dock-surface={variant} className={cn(className)}>
      {children}
    </div>
  );
}

export interface DockPromptProps {
  children: ReactNode;
  /** Tipo de aviso: decide el color del borde superior y del icono. */
  kind?: "permission" | "question" | "todo" | "revert";
  className?: string;
  onKeyDown?: React.KeyboardEventHandler<HTMLDivElement>;
}

export function DockPrompt({ children, kind = "permission", className, onKeyDown }: DockPromptProps) {
  return (
    <div
      data-component="dock-prompt"
      data-kind={kind}
      tabIndex={-1}
      onKeyDown={onKeyDown}
      className={cn("flex w-full shrink-0 flex-col", className)}
    >
      {children}
    </div>
  );
}
