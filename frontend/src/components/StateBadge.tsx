import type { AssessmentState } from "../api/client";

const LABELS: Record<AssessmentState, string> = {
  draft: "Draft",
  queued: "Queued",
  running: "Running",
  cancelling: "Cancelling",
  completed: "Completed",
  completed_with_errors: "Completed with errors",
  failed: "Failed",
  cancelled: "Cancelled",
};

export function StateBadge({ state }: { state: AssessmentState }) {
  return <span className={"state-badge state-" + state}>{LABELS[state]}</span>;
}
