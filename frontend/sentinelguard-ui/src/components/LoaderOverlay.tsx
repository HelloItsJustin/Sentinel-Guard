import { useEffect } from "react";

export function LoaderOverlay(props: { open: boolean; title: string; subtitle?: string }) {
  useEffect(() => {
    if (!props.open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prev;
    };
  }, [props.open]);

  if (!props.open) return null;

  return (
    <div className="overlay">
      <div className="overlayCard">
        <div className="overlayHeader">
          <div className="spinner" aria-hidden="true" />
          <div>
            <div className="overlayTitle">{props.title}</div>
            {props.subtitle ? <div className="overlaySubtitle">{props.subtitle}</div> : null}
          </div>
        </div>
        <div className="overlaySteps">
          <div className="overlayStep">Detecting secrets &amp; PII...</div>
          <div className="overlayStep">Applying enterprise policy...</div>
          <div className="overlayStep">Generating sanitized prompt...</div>
          <div className="overlayStep">Writing audit log...</div>
        </div>
      </div>
    </div>
  );
}
