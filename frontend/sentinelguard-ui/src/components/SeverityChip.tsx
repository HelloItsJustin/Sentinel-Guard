export function SeverityChip({ risk }: { risk: string }) {
  const r = (risk || "").toUpperCase();
  const cls =
    r === "HIGH" ? "badge badge-high" : r === "MEDIUM" ? "badge badge-medium" : "badge badge-low";
  return <span className={cls}>{r}</span>;
}
