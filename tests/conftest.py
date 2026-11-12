import pytest

from marlowe.pipeline import analyse_auth_log
from marlowe.synthetic import generate_auth_log


@pytest.fixture(scope="session")
def analysis(tmp_path_factory):
    """One full analysis of the default synthetic log, shared across tests (it takes ~1 s)."""
    d = tmp_path_factory.mktemp("analysis")
    generate_auth_log().write(d / "auth.log", d / "labels.csv")
    return analyse_auth_log(d / "auth.log", d / "manifest.jsonl", year=2026)
