import { getIssueDescription } from "../lib/issueDescriptions";

export function IssueChip({ issue }: { issue: string }) {
  const description = getIssueDescription(issue);
  return (
    <span className="issueChip">
      {issue}
      <span className="chipTooltip">{description}</span>
    </span>
  );
}

export function IssueChipList({ issues }: { issues: string[] }) {
  if (!issues.length) {
    return <span className="issueChip">No issues</span>;
  }
  return (
    <>
      {issues.map((i) => (
        <IssueChip key={i} issue={i} />
      ))}
    </>
  );
}
