/**
 * Accordion - listas plegables sobre Radix UI. Es la pieza que sostiene la
 * traza de herramientas de la consola del agente (equivalente a
 * `session-ui/src/components/basic-tool.tsx` + `accordion.css` de opencode):
 * cabecera siempre visible con estado, contenido con la evidencia completa.
 */
import * as Radix from "@radix-ui/react-accordion";
import type { ComponentProps } from "react";
import { Icon } from "./icon";
import { cn } from "./lib/cn";
import "./accordion.css";

export const Accordion = Radix.Root;

export function AccordionItem({ className, ...rest }: ComponentProps<typeof Radix.Item>) {
  return <Radix.Item data-component="accordion-item" className={cn(className)} {...rest} />;
}

export function AccordionTrigger({
  className,
  children,
  ...rest
}: ComponentProps<typeof Radix.Trigger>) {
  return (
    <Radix.Header data-slot="accordion-header">
      <Radix.Trigger data-slot="accordion-trigger" className={cn(className)} {...rest}>
        {children}
        <span data-slot="accordion-chevron">
          <Icon name="chevron-down" size="small" />
        </span>
      </Radix.Trigger>
    </Radix.Header>
  );
}

export function AccordionContent({ className, children, ...rest }: ComponentProps<typeof Radix.Content>) {
  return (
    <Radix.Content
      data-slot="accordion-content"
      className={cn("accordion-content", className)}
      {...rest}
    >
      <div data-slot="accordion-content-inner">{children}</div>
    </Radix.Content>
  );
}
