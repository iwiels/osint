/** Tag - etiqueta compacta de metadatos (estado del caso, proveedor, tipo de nodo). */
import type { HTMLAttributes, ReactNode } from "react";
import { Icon, type IconName } from "./icon";
import { cn } from "./lib/cn";
import "./tag.css";

export type TagTone =
  | "neutral"
  | "brand"
  | "success"
  | "warning"
  | "critical"
  | "info"
  | "terracotta";

export type TagVariant = "solid" | "dashed" | "stamp";

export interface TagProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: TagTone;
  variant?: TagVariant;
  size?: "normal" | "large";
  icon?: IconName;
  children?: ReactNode;
}

export function Tag({
  tone = "neutral",
  variant = "solid",
  size = "normal",
  icon,
  className,
  children,
  ...rest
}: TagProps) {
  return (
    <span
      data-component="tag"
      data-tone={tone}
      data-variant={variant}
      data-size={size}
      className={cn(className)}
      {...rest}
    >
      {icon ? <Icon name={icon} size="small" /> : null}
      {children}
    </span>
  );
}
