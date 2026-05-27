import { ReactNode, useEffect } from "react";
import { Icon } from "./Icon";

export function Modal(props: {
  title: string;
  open: boolean;
  onClose: () => void;
  children: ReactNode;
}) {
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") props.onClose();
    }
    if (props.open) window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [props.open, props.onClose]);

  if (!props.open) return null;

  return (
    <div
      className="modalOverlay"
      role="dialog"
      aria-modal="true"
      onMouseDown={props.onClose}
    >
      <div className="modal" onMouseDown={(e) => e.stopPropagation()}>
        <div className="modalHeader">
          <div className="modalTitle">{props.title}</div>
          <button className="iconButton" onClick={props.onClose} type="button" aria-label="Close dialog" title="Close">
            <Icon name="x" size={17} />
          </button>
        </div>
        {props.children}
      </div>
    </div>
  );
}
