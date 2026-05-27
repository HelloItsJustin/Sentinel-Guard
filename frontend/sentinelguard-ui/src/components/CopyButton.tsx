import { useState } from "react";
import { Icon } from "./Icon";

export function CopyButton({ text, label = "Copy", small = false }: { text: string; label?: string; small?: boolean }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // fallback
    }
  }

  return (
    <button
      type="button"
      className={small ? "copyBtn btnSm" : "copyBtn"}
      onClick={handleCopy}
      title={copied ? "Copied" : "Copy to clipboard"}
    >
      <Icon name={copied ? "check" : "copy"} size={small ? 14 : 16} />
      {copied ? "Copied" : label}
    </button>
  );
}
