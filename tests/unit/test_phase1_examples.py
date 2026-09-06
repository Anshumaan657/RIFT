import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from rift.domain.schemas import AssessmentConfiguration, CheckResult

ROOT = Path(__file__).parents[2]
EXAMPLES = ROOT / "docs" / "examples"


def load(name: str) -> object:
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def test_assessment_example_matches_schema() -> None:
    model = AssessmentConfiguration.model_validate(load("assessment-configuration.json"))
    assert len(model.selected_checks) == 3


@pytest.mark.parametrize(
    "name",
    ["authn-check-result.json", "authz-check-result.json", "config-check-result.json"],
)
def test_check_result_examples_match_schema(name: str) -> None:
    CheckResult.model_validate(load(name))


def test_unknown_contract_fields_are_rejected() -> None:
    data = load("assessment-configuration.json")
    assert isinstance(data, dict)
    data["unexpected"] = True
    with pytest.raises(ValidationError):
        AssessmentConfiguration.model_validate(data)
