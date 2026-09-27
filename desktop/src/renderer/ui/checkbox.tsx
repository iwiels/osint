/** Checkbox - casilla booleana sobre Radix UI. */
import * as Radix from "@radix-ui/react-checkbox";
import { useId } from "react";
import type { ComponentProps } from "react";
import { Icon } from "./icon";
import { cn } from "./lib/cn";
import "./checkbox.css";

export interface CheckboxProps extends ComponentProps<typeof Radix.Root> {
  label?: string;
}

export function Checkbox({ label, className, id, ...rest }: CheckboxProps) {
  // Sin `id` explícito, el `htmlFor` de la etiqueta no asociaría nada: se
  // genera uno para que el nombre accesible llegue siempre al lector.
  const autoId = useId();
  const controlId = id ?? autoId;
  const control = (
    <Radix.Root
      id={controlId}
      data-component="checkbox"
      className={cn(className)}
      {...rest}
    >
      <Radix.Indicator data-slot="checkbox-indicator">
        <Icon name="check" size="small" />
      </Radix.Indicator>
    </Radix.Root>
  );

  if (!label) return control;

  return (
    <label data-component="checkbox-field" htmlFor={controlId}>
      {control}
      <span data-slot="checkbox-label">{label}</span>
    </label>
  );
}
