/** Switch - interruptor booleano sobre Radix UI (opciones de configuración). */
import * as Radix from "@radix-ui/react-switch";
import { useId } from "react";
import type { ComponentProps } from "react";
import { cn } from "./lib/cn";
import "./switch.css";

export interface SwitchProps extends ComponentProps<typeof Radix.Root> {
  label?: string;
}

export function Switch({ label, className, id, ...rest }: SwitchProps) {
  const autoId = useId();
  const controlId = id ?? autoId;
  const control = (
    <Radix.Root id={controlId} data-component="switch" className={cn(className)} {...rest}>
      <Radix.Thumb data-slot="switch-thumb" />
    </Radix.Root>
  );

  if (!label) return control;

  return (
    <label data-component="switch-field" htmlFor={controlId}>
      {control}
      <span data-slot="switch-label">{label}</span>
    </label>
  );
}
