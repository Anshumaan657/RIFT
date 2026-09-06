"""Explicit assessment and job state machines."""

from datetime import UTC, datetime

from rift.domain.models import Assessment, AssessmentState, Job, JobState

ASSESSMENT_TRANSITIONS: dict[AssessmentState, frozenset[AssessmentState]] = {
    AssessmentState.DRAFT: frozenset({AssessmentState.QUEUED, AssessmentState.CANCELLED}),
    AssessmentState.QUEUED: frozenset(
        {AssessmentState.RUNNING, AssessmentState.CANCELLING, AssessmentState.CANCELLED}
    ),
    AssessmentState.RUNNING: frozenset(
        {
            AssessmentState.CANCELLING,
            AssessmentState.COMPLETED,
            AssessmentState.COMPLETED_WITH_ERRORS,
            AssessmentState.FAILED,
        }
    ),
    AssessmentState.CANCELLING: frozenset({AssessmentState.CANCELLED}),
    AssessmentState.COMPLETED: frozenset(),
    AssessmentState.COMPLETED_WITH_ERRORS: frozenset(),
    AssessmentState.FAILED: frozenset(),
    AssessmentState.CANCELLED: frozenset(),
}

JOB_TRANSITIONS: dict[JobState, frozenset[JobState]] = {
    JobState.PENDING: frozenset({JobState.CLAIMED, JobState.CANCELLED}),
    JobState.CLAIMED: frozenset({JobState.RUNNING, JobState.PENDING, JobState.CANCELLED}),
    JobState.RUNNING: frozenset({JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELLED}),
    JobState.SUCCEEDED: frozenset(),
    JobState.FAILED: frozenset(),
    JobState.CANCELLED: frozenset(),
}


class InvalidStateTransition(ValueError):
    pass


def transition_assessment(
    assessment: Assessment,
    new_state: AssessmentState,
    *,
    reason: str | None = None,
    now: datetime | None = None,
) -> None:
    current = assessment.state
    if new_state not in ASSESSMENT_TRANSITIONS[current]:
        raise InvalidStateTransition(f"assessment cannot transition from {current} to {new_state}")
    timestamp = now or datetime.now(UTC)
    assessment.state = new_state
    if new_state == AssessmentState.RUNNING:
        assessment.started_at = timestamp
    if new_state == AssessmentState.CANCELLING:
        assessment.cancelled_at = timestamp
    if new_state == AssessmentState.CANCELLED:
        assessment.cancelled_at = assessment.cancelled_at or timestamp
        assessment.completed_at = timestamp
    if new_state in {
        AssessmentState.COMPLETED,
        AssessmentState.COMPLETED_WITH_ERRORS,
        AssessmentState.FAILED,
    }:
        assessment.completed_at = timestamp
    if reason is not None:
        assessment.terminal_reason = reason


def transition_job(job: Job, new_state: JobState) -> None:
    if new_state not in JOB_TRANSITIONS[job.state]:
        raise InvalidStateTransition(f"job cannot transition from {job.state} to {new_state}")
    job.state = new_state
