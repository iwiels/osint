/** DropdownMenu - menú de acciones sobre Radix UI (fila de caso, informe, nodo). */
import * as Radix from "@radix-ui/react-dropdown-menu";
import type { ComponentProps } from "react";
import { cn } from "./lib/cn";
import "./dropdown-menu.css";

export const DropdownMenu = Radix.Root;
export const DropdownMenuTrigger = Radix.Trigger;
export const DropdownMenuGroup = Radix.Group;
export const DropdownMenuSub = Radix.Sub;
export const DropdownMenuSubTrigger = Radix.SubTrigger;
export const DropdownMenuRadioGroup = Radix.RadioGroup;

export function DropdownMenuContent({
  className,
  sideOffset = 4,
  align = "start",
  ...rest
}: ComponentProps<typeof Radix.Content>) {
  return (
    <Radix.Portal>
      <Radix.Content
        data-component="dropdown-menu"
        sideOffset={sideOffset}
        align={align}
        className={cn(className)}
        {...rest}
      />
    </Radix.Portal>
  );
}

export function DropdownMenuSubContent({
  className,
  sideOffset = 2,
  ...rest
}: ComponentProps<typeof Radix.SubContent>) {
  return (
    <Radix.Portal>
      <Radix.SubContent
        data-component="dropdown-menu"
        data-sub=""
        sideOffset={sideOffset}
        className={cn(className)}
        {...rest}
      />
    </Radix.Portal>
  );
}

export function DropdownMenuItem({ className, ...rest }: ComponentProps<typeof Radix.Item>) {
  return <Radix.Item data-slot="dropdown-menu-item" className={cn(className)} {...rest} />;
}

export function DropdownMenuCheckboxItem({
  className,
  ...rest
}: ComponentProps<typeof Radix.CheckboxItem>) {
  return <Radix.CheckboxItem data-slot="dropdown-menu-item" className={cn(className)} {...rest} />;
}

export function DropdownMenuRadioItem({ className, ...rest }: ComponentProps<typeof Radix.RadioItem>) {
  return <Radix.RadioItem data-slot="dropdown-menu-item" className={cn(className)} {...rest} />;
}

export function DropdownMenuLabel({ className, ...rest }: ComponentProps<typeof Radix.Label>) {
  return <Radix.Label data-slot="dropdown-menu-label" className={cn(className)} {...rest} />;
}

export function DropdownMenuSeparator({ className, ...rest }: ComponentProps<typeof Radix.Separator>) {
  return <Radix.Separator data-slot="dropdown-menu-separator" className={cn(className)} {...rest} />;
}
