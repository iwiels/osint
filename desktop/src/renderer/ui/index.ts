/**
 * Capa `ui/` — primitivas de interfaz, sin lógica de negocio ni acceso a datos.
 *
 * Equivale a `packages/ui/src/components/*` de opencode: cada primitiva vive en
 * su archivo con su CSS hermano (`button.tsx` + `button.css`) y expone su
 * contrato por atributos (`data-component` / `data-slot` / `data-variant`) para
 * que el CSS no dependa de clases utilitarias del consumidor.
 *
 * Todo lo que se consume desde aquí se importa del barrel:
 *   import { Button, IconButton, Tag, useAutoScroll } from "@renderer/ui";
 */

// Base
export { Icon, type IconName, type IconProps } from "./icon";
export { cn, type ClassValue } from "./lib/cn";

// Acciones
export { Button, type ButtonProps, type ButtonSize, type ButtonVariant } from "./button";
export { IconButton, type IconButtonProps } from "./icon-button";
export { Keybind, type KeybindProps } from "./keybind";
export { Spinner, type SpinnerProps } from "./spinner";

// Formularios
export { TextField, TextArea, type TextFieldProps, type TextAreaProps } from "./text-field";
export {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
} from "./select";
export { Checkbox, type CheckboxProps } from "./checkbox";
export { Switch, type SwitchProps } from "./switch";

// Contenedores y navegación
export { Tabs, TabsContent, TabsList, TabsTrigger } from "./tabs";
export { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "./accordion";
export { Collapsible, CollapsibleContent, CollapsibleTrigger } from "./collapsible";
export { ScrollView, type ScrollViewProps } from "./scroll-view";

// Superficies flotantes
export {
  Dialog,
  DialogBody,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "./dialog";
export { Popover, PopoverAnchor, PopoverClose, PopoverContent, PopoverTrigger } from "./popover";
export { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "./tooltip";
export {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "./dropdown-menu";

// Presentación
export { Tag, type TagProps, type TagTone, type TagVariant } from "./tag";
export { DockPrompt, DockSurface, type DockPromptProps, type DockSurfaceProps } from "./dock-surface";

// Hooks
export { useAutoScroll, type AutoScrollApi, type UseAutoScrollOptions } from "./hooks";
