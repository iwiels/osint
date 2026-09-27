/**
 * Button - acción principal del sistema.
 * Portado de `packages/ui/src/components/button.tsx` (opencode) a React:
 * mismas variantes/tamaños y contrato por atributos (`data-component`,
 * `data-variant`, `data-size`, `data-icon`) que el CSS consume.
 *
 * Reenvía la ref y el resto de props nativas: se puede usar como
 * `asChild` de los triggers de Radix (Tooltip, Dialog, DropdownMenu…).
 */

import { forwardRef } from "react";
import type { ButtonHTMLAttributes } from "react";
import { Icon, type IconName } from "./icon";
import { cn } from "./lib/cn";
import "./button.css";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "terracotta";
export type ButtonSize = "small" | "normal" | "large";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Icono a la izquierda del texto. */
  icon?: IconName;
  /** Icono a la derecha (chevrones, indicadores de despliegue). */
  iconAfter?: IconName;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    variant = "secondary",
    size = "normal",
    icon,
    iconAfter,
    className,
    children,
    type = "button",
    ...rest
  },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      data-component="button"
      data-variant={variant}
      data-size={size}
      data-icon={icon ? "" : undefined}
      data-icon-after={iconAfter ? "" : undefined}
      className={cn(className)}
      {...rest}
    >
      {icon ? <Icon name={icon} size="small" /> : null}
      {children}
      {iconAfter ? <Icon name={iconAfter} size="small" /> : null}
    </button>
  );
});
