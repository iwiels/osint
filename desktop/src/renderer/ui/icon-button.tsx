/**
 * IconButton - botón cuadrado sólo-icono (cerrar, recargar, copiar…).
 * Portado de `components/icon-button.tsx` de opencode. Exige `label` para
 * que quede un `aria-label` en el DOM: es un botón sin texto visible.
 */

import { forwardRef } from "react";
import type { ButtonHTMLAttributes } from "react";
import { Icon, type IconName, type IconProps } from "./icon";
import { cn } from "./lib/cn";
import type { ButtonVariant } from "./button";
import "./icon-button.css";

export interface IconButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "children"> {
  name: IconName;
  /** Texto para lectores de pantalla y tooltip nativo. */
  label: string;
  variant?: ButtonVariant;
  size?: "small" | "normal" | "large";
  tone?: IconProps["tone"];
}

export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  { name, label, variant = "ghost", size = "normal", tone, className, ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type="button"
      data-component="icon-button"
      data-variant={variant}
      data-size={size}
      className={cn(className)}
      aria-label={label}
      {...rest}
      title={rest.title ?? label}
    >
      <Icon name={name} size={size === "large" ? "medium" : "small"} tone={tone} />
    </button>
  );
});
