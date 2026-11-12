import json

import pytest

from marlowe.assistant import AnalysisTools


@pytest.fixture
def tools(analysis):
    return AnalysisTools(analysis)


def call(tools, name, **kwargs):
    return json.loads(tools.call(name, kwargs))


def test_schemas_are_valid_tool_definitions(tools):
    names = set()
    for schema in tools.schemas():
        assert schema["type"] == "function"
        fn = schema["function"]
        assert fn["name"] and fn["description"]
        assert fn["parameters"]["type"] == "object"
        names.add(fn["name"])
    assert names == {
        "get_overview",
        "list_findings",
        "get_finding",
        "get_log_lines",
        "ip_activity",
        "user_activity",
    }


def test_overview(tools, analysis):
    out = call(tools, "get_overview")
    assert out["evidence"]["sha256"] == analysis.evidence.sha256
    assert out["total_lines"] == len(analysis.events)
    assert out["n_findings"] > 0


def test_list_findings_bounded_and_ordered(tools):
    out = call(tools, "list_findings", limit=1000)
    assert out["returned"] <= 25
    scores = [f["anomaly_score"] for f in out["findings"]]
    assert scores == sorted(scores, reverse=True)
    assert out["findings"][0]["finding_id"] == "F1"


def test_list_findings_filter(tools):
    rules = call(tools, "list_findings", detector="rules")
    assert all(f["flagged_by_rules"] for f in rules["findings"])
    assert "error" in call(tools, "list_findings", detector="magic")


def test_no_ground_truth_leaks_to_the_model(analysis):
    # Even when the analysis was run with labels, no tool output may contain them.
    tools = AnalysisTools(analysis)
    tools.findings["is_attack"] = 1  # simulate labelled data being present
    tools.findings["attack_ids"] = "A01"
    blob = tools.call("list_findings", {"limit": 25}) + tools.call(
        "get_finding", {"finding_id": "F1"}
    )
    assert "is_attack" not in blob and "attack_id" not in blob and "A01" not in blob


def test_get_finding(tools):
    out = call(tools, "get_finding", finding_id="f1")  # case-insensitive
    assert out["finding_id"] == "F1"
    assert "n_failed" in out["features"]
    assert out["line_nos"]
    assert "error" in call(tools, "get_finding", finding_id="F9999")


def test_get_log_lines_bounded_and_marked_untrusted(tools, analysis):
    out = call(tools, "get_log_lines", start_line=1, end_line=500)
    assert out["truncated_to_max_lines"]
    assert len(out["untrusted_log_lines"]) == 40
    assert out["untrusted_log_lines"][0] == {"line_no": 1, "text": analysis.events.iloc[0]["raw"]}
    assert "error" in call(tools, "get_log_lines", start_line=10**7)


def test_ip_and_user_activity(tools, analysis):
    ip = analysis.findings().iloc[0]["src_ip"]
    out = call(tools, "ip_activity", src_ip=ip)
    assert out["src_ip"] == ip and "F1" in out["flagged_findings"]
    assert "error" in call(tools, "ip_activity", src_ip="1.1.1.1")

    out = call(tools, "user_activity", user="alice")
    assert out["n_successful_logins"] > 0
    assert "error" in call(tools, "user_activity", user="nobody")


def test_bad_calls_return_errors_not_exceptions(tools):
    assert "error" in call(tools, "rm_rf")
    assert "error" in json.loads(tools.call("get_finding", {}))
    assert "error" in json.loads(tools.call("get_finding", "{not json"))
    assert "error" in json.loads(tools.call("get_overview", {"surprise": 1}))
    assert "error" in json.loads(tools.call("get_log_lines", {"start_line": "ten"}))
