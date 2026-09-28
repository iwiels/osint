/**
 * Dialog - ventana modal sobre Radix UI (configuración de modelo, permisos,
 * confirmaciones). Los docks de la consola NO usan Dialog: van anclados sobre
 * el compositor (ver `dock-surface`) para no bloquear el análisis.
 */
import * as Radix from "@radix-ui/react-dialog";
import type { ComponentProps } from "react";
import { IconButton } from "./icon-button";
import { cn } from "./lib/cn";
import "./dialog.css";

export const Dialog = Radix.Root;
export const DialogTrigger = Radix.Trigger;
export const DialogClose = Radix.Close;

export function DialogContent({
  className,
  children,
  size = "normal",
  title,
  description,
  ...rest
}: ComponentProps<typeof Radix.Content> & {
  size?: "small" | "normal" | "large" | "x-large";
  /** Nombre accesible del diálogo. Obligatorio salvo que pases `DialogTitle`. */
  title?: string;
  description?: string;
}) {
  return (
    <Radix.Portal>
      <Radix.Overlay data-slot="dialog-overlay" />
      <Radix.Content
        data-component="dialog"
        data-size={size}
        className={cn(className)}
        {...rest}
      >
        {title ? (
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
            {description ? <DialogDescription>{description}</DialogDescription> : null}
          </DialogHeader>
        ) : null}
        {children}
        <Radix.Close asChild>
          <IconButton
            name="close"
            label="Cerrar"
            size="small"
            data-slot="dialog-close"
            className="absolute right-2 top-2"
          />
        </Radix.Close>
      </Radix.Content>
    </Radix.Portal>
  );
}

export function DialogHeader({ className, ...rest }: ComponentProps<"div">) {
  return <div data-slot="dialog-header" className={cn(className)} {...rest} />;
}

export function DialogTitle({ className, ...rest }: ComponentProps<typeof Radix.Title>) {
  return <Radix.Title data-slot="dialog-title" className={cn(className)} {...rest} />;
}

export function DialogDescription({ className, ...rest }: ComponentProps<typeof Radix.Description>) {
  return <Radix.Description data-slot="dialog-description" className={cn(className)} {...rest} />;
}

export function DialogBody({ className, ...rest }: ComponentProps<"div">) {
  return <div data-slot="dialog-body" className={cn(className)} {...rest} />;
}

export function DialogFooter({ className, ...rest }: ComponentProps<"div">) {
  return <div data-slot="dialog-footer" className={cn(className)} {...rest} />;
}
