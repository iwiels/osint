/**
 * Tooltip - ayuda contextual sobre Radix UI. Un único `TooltipProvider` en la
 * raíz de la app fija el retardo (ver App.tsx) para que todos los tooltips
 * aparezcan al mismo ritmo.
 */
import * as Radix from "@radix-ui/react-tooltip";
import type { ComponentProps } from "react";
import { cn } from "./lib/cn";
import "./tooltip.css";

export const TooltipProvider = Radix.Provider;
export const Tooltip = Radix.Root;
export const TooltipTrigger = Radix.Trigger;

export function TooltipContent({
  className,
  children,
  sideOffset = 6,
  ...rest
}: ComponentProps<typeof Radix.Content>) {
  return (
    <Radix.Portal>
      <Radix.Content
        data-component="tooltip"
        sideOffset={sideOffset}
        className={cn(className)}
        {...rest}
      >
        {children}
        <Radix.Arrow data-slot="tooltip-arrow" width={10} height={5} />
      </Radix.Content>
    </Radix.Portal>
  );
}
