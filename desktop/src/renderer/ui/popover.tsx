/**
 * Popover - panel flotante anclado a un disparador. Es el sustituto correcto
 * del overlay `fixed inset-0` que usaba la consola para los ajustes de modelo:
 * no tapa la interfaz y se cierra al perder el foco.
 */
import * as Radix from "@radix-ui/react-popover";
import type { ComponentProps } from "react";
import { cn } from "./lib/cn";
import "./popover.css";

export const Popover = Radix.Root;
export const PopoverTrigger = Radix.Trigger;
export const PopoverAnchor = Radix.Anchor;
export const PopoverClose = Radix.Close;

export function PopoverContent({
  className,
  children,
  sideOffset = 6,
  align = "end",
  ...rest
}: ComponentProps<typeof Radix.Content>) {
  return (
    <Radix.Portal>
      <Radix.Content
        data-component="popover"
        sideOffset={sideOffset}
        align={align}
        className={cn(className)}
        {...rest}
      >
        {children}
      </Radix.Content>
    </Radix.Portal>
  );
}
