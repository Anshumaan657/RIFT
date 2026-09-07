"""Run one approved check and normalize policy/cancellation outcomes."""

from datetime import UTC, datetime

from rift.domain.models import CheckOutcome
from rift.engine.checks import authn, authz, config
from rift.engine.checks.common import result
from rift.engine.contracts import CheckResult, ControlledClient, ResourceInput
from rift.safety.http_client import (
    BudgetExceededError,
    CancellationError,
    PolicyError,
    RuntimeExceededError,
)


async def run_check(
    identifier: str,
    client: ControlledClient,
    *,
    resource: ResourceInput | None,
    is_https: bool,
) -> CheckResult:
    started = datetime.now(UTC)
    try:
        if identifier == authn.IDENTIFIER:
            return await authn.run(client, resource)
        if identifier == authz.IDENTIFIER:
            return await authz.run(client, resource)
        if identifier == config.IDENTIFIER:
            return await config.run(client, is_https=is_https)
        return result(
            identifier,
            started,
            CheckOutcome.SKIPPED,
            "UNSUPPORTED_CHECK",
            "The check is not in the approved V1 catalogue.",
        )
    except CancellationError:
        return result(
            identifier,
            started,
            CheckOutcome.CANCELLED,
            "ASSESSMENT_CANCELLED",
            "The assessment was cancelled before the request completed.",
        )
    except BudgetExceededError:
        return result(
            identifier,
            started,
            CheckOutcome.ERROR,
            "REQUEST_BUDGET_EXHAUSTED",
            "The server-owned request budget was exhausted.",
        )
    except RuntimeExceededError:
        return result(
            identifier,
            started,
            CheckOutcome.ERROR,
            "RUNTIME_EXPIRED",
            "The assessment runtime limit expired.",
        )
    except PolicyError as exc:
        return result(
            identifier,
            started,
            CheckOutcome.ERROR,
            "SAFETY_POLICY_REJECTED",
            f"The controlled client rejected the request: {exc}",
        )
