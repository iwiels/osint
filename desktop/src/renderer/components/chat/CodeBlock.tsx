import React, { useMemo, useState } from "react";
import { Button, Icon } from "../../ui";

export interface CodeBlockProps {
  children?: React.ReactNode;
  className?: string;
  language?: string;
  code?: string;
}

function extractText(node: React.ReactNode): string {
  if (typeof node === "string") return node;
  if (typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(extractText).join("");
  if (React.isValidElement(node)) {
    const props = node.props as { children?: React.ReactNode };
    return props.children ? extractText(props.children) : "";
  }
  return "";
}

export function CodeBlock({ children, className, language, code }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  // Detect language and extract raw string from ReactMarkdown structure (<pre><code className="language-xxx">...</code></pre>)
  const { detectedLanguage, rawCode } = useMemo(() => {
    let lang = language || "";
    let extracted = code || "";

    if (!extracted && children) {
      if (React.isValidElement(children)) {
        const childProps = children.props as { className?: string; children?: React.ReactNode };
        if (childProps.className) {
          const match = /language-([a-zA-Z0-9_-]+)/i.exec(childProps.className);
          if (match) lang = match[1];
        }
        extracted = extractText(childProps.children ?? children);
      } else {
        extracted = extractText(children);
      }
    }

    return {
      detectedLanguage: lang.toLowerCase(),
      rawCode: extracted.replace(/\n$/, ""),
    };
  }, [children, language, code]);

  const handleCopy = async () => {
    if (!rawCode) return;
    try {
      await navigator.clipboard.writeText(rawCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard access error
    }
  };

  const displayLang = detectedLanguage ? detectedLanguage.toUpperCase() : "CODE";

  return (
    <div
      data-component="code-block"
      className={`relative my-2.5 overflow-hidden rounded-md border border-border-weak-base bg-surface-inset-base shadow-xs ${className ?? ""}`}
    >
      <div className="flex h-7 items-center justify-between border-b border-border-weak-base bg-surface-raised-strong/50 px-3 py-1 text-[10px] font-mono">
        <span className="font-semibold tracking-wider text-text-weak uppercase">
          {displayLang}
        </span>
        <Button
          variant="ghost"
          size="small"
          onClick={handleCopy}
          className="h-5 px-1.5 font-mono text-[10px] text-text-weak hover:text-text-brand"
          title="Copiar código"
        >
          <Icon name={copied ? "check" : "copy"} size="small" tone={copied ? "success" : "weak"} />
          <span>{copied ? "Copiado" : "Copiar"}</span>
        </Button>
      </div>

      <pre className="max-h-96 overflow-x-auto p-3 font-mono text-[11.5px] leading-relaxed text-text-strong select-text break-words whitespace-pre-wrap">
        <code>{rawCode || children}</code>
      </pre>
    </div>
  );
}
export default CodeBlock;
