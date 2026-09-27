/**
 * Tabs - navegación por pestañas sobre Radix UI. Variantes:
 *   underline → pestañas de vista (vista de caso: grafo, custodia, …)
 *   pill      → conmutadores compactos dentro de un panel
 */
import * as Radix from "@radix-ui/react-tabs";
import type { ComponentProps } from "react";
import { cn } from "./lib/cn";
import "./tabs.css";

export const Tabs = Radix.Root;

export function TabsList({
  variant = "underline",
  className,
  ...rest
}: ComponentProps<typeof Radix.List> & { variant?: "underline" | "pill" }) {
  return (
    <Radix.List
      data-component="tabs"
      data-slot="tabs-list"
      data-variant={variant}
      className={cn(className)}
      {...rest}
    />
  );
}

export function TabsTrigger({ className, ...rest }: ComponentProps<typeof Radix.Trigger>) {
  return (
    <Radix.Trigger data-slot="tabs-trigger" className={cn(className)} {...rest} />
  );
}

export function TabsContent({ className, ...rest }: ComponentProps<typeof Radix.Content>) {
  return <Radix.Content data-slot="tabs-content" className={cn(className)} {...rest} />;
}
