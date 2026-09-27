/**
 * Select - lista desplegable accesible sobre Radix UI (equivalente React del
 * Kobalte Select que usa opencode). Igual que allí, el componente no intenta
 * ser "todo en uno": se exponen las partes y el consumidor compone.
 *
 *   <Select value={provider} onValueChange={setProvider}>
 *     <SelectTrigger><SelectValue /></SelectTrigger>
 *     <SelectContent>
 *       <SelectItem value="opencode">OpenCode Zen</SelectItem>
 *     </SelectContent>
 *   </Select>
 */

import * as Radix from "@radix-ui/react-select";
import type { ComponentProps } from "react";
import { Icon } from "./icon";
import { cn } from "./lib/cn";
import "./select.css";

export const Select = Radix.Root;
export const SelectGroup = Radix.Group;
export const SelectValue = Radix.Value;

export function SelectTrigger({ className, children, ...rest }: ComponentProps<typeof Radix.Trigger>) {
  return (
    <Radix.Trigger data-component="select" data-slot="select-trigger" className={cn(className)} {...rest}>
      {children}
      <Radix.Icon data-slot="select-icon" asChild>
        <span>
          <Icon name="chevron-down" size="small" />
        </span>
      </Radix.Icon>
    </Radix.Trigger>
  );
}

export function SelectContent({
  className,
  children,
  position = "popper",
  ...rest
}: ComponentProps<typeof Radix.Content>) {
  return (
    <Radix.Portal>
      <Radix.Content
        data-component="select"
        data-slot="select-content"
        position={position}
        sideOffset={4}
        className={cn(className)}
        {...rest}
      >
        <Radix.Viewport data-slot="select-viewport">{children}</Radix.Viewport>
      </Radix.Content>
    </Radix.Portal>
  );
}

export function SelectLabel({ className, ...rest }: ComponentProps<typeof Radix.Label>) {
  return <Radix.Label data-slot="select-label" className={cn(className)} {...rest} />;
}

export function SelectItem({ className, children, ...rest }: ComponentProps<typeof Radix.Item>) {
  return (
    <Radix.Item data-slot="select-item" className={cn(className)} {...rest}>
      <Radix.ItemIndicator data-slot="select-item-indicator">
        <Icon name="check-small" size="small" />
      </Radix.ItemIndicator>
      <Radix.ItemText>{children}</Radix.ItemText>
    </Radix.Item>
  );
}

export function SelectSeparator({ className, ...rest }: ComponentProps<typeof Radix.Separator>) {
  return <Radix.Separator data-slot="select-separator" className={cn(className)} {...rest} />;
}
