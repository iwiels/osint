/**
 * ScrollView - contenedor de scroll con estilos consistentes. Se usa junto a
 * `useAutoScroll`: el `ref` que se pasa aquí es el que el hook necesita.
 */
import { forwardRef } from "react";
import type { HTMLAttributes, ReactNode } from "react";
import { cn } from "./lib/cn";
import "./scroll-view.css";

export interface ScrollViewProps extends HTMLAttributes<HTMLDivElement> {
  direction?: "vertical" | "horizontal" | "both";
  /** Contenido interno (lo que crece mientras el agente trabaja). */
  children?: ReactNode;
}

export const ScrollView = forwardRef<HTMLDivElement, ScrollViewProps>(function ScrollView(
  { direction = "vertical", className, children, ...rest },
  ref,
) {
  return (
    <div data-component="scroll-view" className={cn(className)} {...rest}>
      <div ref={ref} data-slot="scroll-view-viewport" data-direction={direction}>
        {children}
      </div>
    </div>
  );
});
