/**
 * TextField / TextArea - entrada de texto con etiqueta, descripción y error.
 * Equivalente React de `components/text-field.tsx` de opencode: el estado de
 * validación se expone en atributos (`data-invalid`, `data-disabled`) y el CSS
 * decide el color, en vez de condicionales de clase en el JSX.
 */

import { forwardRef, useId } from "react";
import type { InputHTMLAttributes, TextareaHTMLAttributes } from "react";
import { cn } from "./lib/cn";
import "./text-field.css";

// `size` nativo (number) se sustituye por la escala del sistema, de ahí el Omit.
export interface TextFieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "size"> {
  label?: string;
  description?: string;
  error?: string;
  /** Ancho del campo cuando el layout no lo estira. */
  size?: "small" | "normal";
}

export const TextField = forwardRef<HTMLInputElement, TextFieldProps>(function TextField(
  { label, description, error, size = "normal", className, id, ...rest },
  ref,
) {
  const autoId = useId();
  const inputId = id ?? autoId;
  const describedBy = error ? `${inputId}-error` : description ? `${inputId}-description` : undefined;

  return (
    <div
      data-component="text-field"
      data-invalid={error ? "" : undefined}
      data-disabled={rest.disabled ? "" : undefined}
      className={cn(className)}
    >
      {label ? (
        <label data-slot="text-field-label" htmlFor={inputId}>
          {label}
        </label>
      ) : null}
      <input
        ref={ref}
        id={inputId}
        data-slot="text-field-input"
        data-size={size}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
        {...rest}
      />
      {error ? (
        <span data-slot="text-field-error" id={`${inputId}-error`} role="alert">
          {error}
        </span>
      ) : description ? (
        <span data-slot="text-field-description" id={`${inputId}-description`}>
          {description}
        </span>
      ) : null}
    </div>
  );
});

export interface TextAreaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  description?: string;
  error?: string;
}

export const TextArea = forwardRef<HTMLTextAreaElement, TextAreaProps>(function TextArea(
  { label, description, error, className, id, ...rest },
  ref,
) {
  const autoId = useId();
  const areaId = id ?? autoId;
  const describedBy = error ? `${areaId}-error` : description ? `${areaId}-description` : undefined;

  return (
    <div
      data-component="text-field"
      data-variant="area"
      data-invalid={error ? "" : undefined}
      data-disabled={rest.disabled ? "" : undefined}
      className={cn(className)}
    >
      {label ? (
        <label data-slot="text-field-label" htmlFor={areaId}>
          {label}
        </label>
      ) : null}
      <textarea
        ref={ref}
        id={areaId}
        data-slot="text-field-input"
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
        {...rest}
      />
      {error ? (
        <span data-slot="text-field-error" id={`${areaId}-error`} role="alert">
          {error}
        </span>
      ) : description ? (
        <span data-slot="text-field-description" id={`${areaId}-description`}>
          {description}
        </span>
      ) : null}
    </div>
  );
});
