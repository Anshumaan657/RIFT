import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]


def load_script(name: str):  # type: ignore[no-untyped-def]
    path = ROOT / "lab" / "scripts" / name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_manual_verifier_rejects_external_targets() -> None:
    verifier = load_script("verify_lab.py")
    with pytest.raises(ValueError, match="approved HTTP lab"):
        verifier.validate_base_url("https://example.test")


def test_manual_verifier_allows_only_exact_compose_services_when_enabled() -> None:
    verifier = load_script("verify_lab.py")
    assert (
        verifier.validate_base_url(
            "http://lab-vulnerable:8080/", allow_compose_network=True
        )
        == "http://lab-vulnerable:8080/"
    )
    with pytest.raises(ValueError, match="approved"):
        verifier.validate_base_url("http://postgres:5432/", allow_compose_network=True)


def test_seed_reset_is_deterministic(tmp_path: Path) -> None:
    reset = load_script("reset_seed.py")
    first = reset.canonical_seed()
    second = reset.canonical_seed()
    assert first == second
    assert b"RIFT_SYNTHETIC_RECORD_B_7F2A" in first
