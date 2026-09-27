/** Collapsible - sección plegable independiente (historial, plan, ajustes). */
import * as Radix from "@radix-ui/react-collapsible";
import type { ComponentProps } from "react";
import { cn } from "./lib/cn";
import "./collapsible.css";

export const Collapsible = Radix.Root;
export const CollapsibleTrigger = Radix.Trigger;

export function CollapsibleContent({ className, children, ...rest }: ComponentProps<typeof Radix.Content>) {
  return (
    <Radix.Content
      data-slot="collapsible-content"
      className={cn("accordion-content", className)}
      {...rest}
    >
      {children}
    </Radix.Content>
  );
}
