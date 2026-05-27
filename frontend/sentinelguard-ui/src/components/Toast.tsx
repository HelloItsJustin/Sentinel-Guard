import { useEffect } from "react";

export type ToastKind = "safe" | "warn" | "danger" | "info";

export function Toast(props: {
  open: boolean;
  kind: ToastKind;
  title: string;
  message?: string;
  durationMs?: number;
  onClose: () => void;
}) {
  useEffect(() => {
    if (!props.open) return;
    const t = window.setTimeout(props.onClose, props.durationMs ?? 3000);
    return () => window.clearTimeout(t);
  }, [props.open, props.durationMs, props.onClose]);

  if (!props.open) return null;

  return (
    <div className={`toast toast-${props.kind}`} role="status" onClick={props.onClose}>
      <div className="toastTitle">{props.title}</div>
      {props.message ? <div className="toastMsg">{props.message}</div> : null}
      <div className="toastHint">Click to dismiss</div>
    </div>
  );
}
