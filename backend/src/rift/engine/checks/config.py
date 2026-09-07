"""RIFT-CONFIG-001: non-exploitative transport and header observations."""

from datetime import UTC, datetime

from rift.domain.models import CheckOutcome
from rift.engine.checks.common import result
from rift.engine.contracts import CheckResult, ControlledClient, EvidenceCapture

IDENTIFIER = "RIFT-CONFIG-001"
VERSION = "1.0"


async def run(client: ControlledClient, *, is_https: bool, path: str = "/") -> CheckResult:
    started = datetime.now(UTC)
    response = await client.request("HEAD", path)
    method = "HEAD"
    if response.status_code in {405, 501}:
        response = await client.request("GET", path)
        method = "GET"
    capture = EvidenceCapture(method, response.path, {}, response)
    headers = {key.lower(): value for key, value in response.headers.items()}
    content_type = headers.get("content-type", "").lower()
    observations: dict[str, object] = {
        "https": is_https,
        "hsts": bool(headers.get("strict-transport-security")) if is_https else False,
        "csp": bool(headers.get("content-security-policy")) if "html" in content_type else None,
        "x_content_type_options": headers.get("x-content-type-options", "").lower() == "nosniff",
        "referrer_policy": bool(headers.get("referrer-policy")),
    }
    raw_cookie_flags = response.security_metadata.get("cookie_flags", [])
    cookie_flags: list[object] = raw_cookie_flags if isinstance(raw_cookie_flags, list) else []
    observations["cookie_flags"] = cookie_flags
    missing = [key for key, value in observations.items() if value is False]
    for index, flags in enumerate(cookie_flags):
        if isinstance(flags, dict):
            missing.extend(
                f"cookie[{index}].{flag}" for flag, present in flags.items() if present is False
            )
    return result(
        IDENTIFIER,
        started,
        CheckOutcome.FINDING if missing else CheckOutcome.PASSED,
        "CONFIG_OBSERVATIONS_RECORDED",
        "Configuration observations were recorded; missing controls are contextual observations.",
        capture,
        observations={"missing": missing, **observations},
    )
