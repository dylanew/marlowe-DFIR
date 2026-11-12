"""Web app: the data-shaping functions, and a headless run of the Streamlit script."""

from pathlib import Path

import pytest

from marlowe.webapp import views

APP = Path(__file__).resolve().parents[1] / "src" / "marlowe" / "webapp" / "app.py"


def test_save_upload_is_content_addressed_and_read_only(tmp_path):
    a = views.save_upload(b"line one\n", "../../etc/auth.log", tmp_path)
    again = views.save_upload(b"line one\n", "auth.log", tmp_path / "other")
    b = views.save_upload(b"line two\n", "auth.log", tmp_path)
    assert a.parent == tmp_path and a.name.endswith("_auth.log")  # no path traversal
    assert a.name[:12] == again.name[:12] and a != b
    assert a.read_bytes() == b"line one\n"
    assert not a.stat().st_mode & 0o222
    assert views.save_upload(b"line one\n", "auth.log", tmp_path) == a  # reused, not rewritten


def test_overview_stats(analysis):
    s = views.overview_stats(analysis)
    assert s["lines"] == len(analysis.events)
    assert s["findings"] == len(views.findings_table(analysis)) > 0
    assert s["start"] <= s["end"]
    assert s["event_counts"]["lines"].sum() == s["lines"]


def test_findings_table_matches_assistant_ids(analysis):
    from marlowe.assistant import AnalysisTools

    table = views.findings_table(analysis)
    tools = AnalysisTools(analysis)
    f1 = tools.get_finding("F1")
    assert table.at[0, "finding"] == "F1"
    assert table.at[0, "source IP"] == f1["src_ip"]
    assert table["anomaly score"].is_monotonic_decreasing


def test_finding_lines_are_the_raw_evidence(analysis):
    lines = views.finding_lines(analysis, 0, max_lines=5)
    assert 0 < len(lines) <= 5
    raw = analysis.events.set_index("line_no")["raw"]
    assert all(raw[n] == text for n, text in zip(lines["line"], lines["text"], strict=True))


def test_chart_data(analysis):
    hourly = views.hourly_activity(analysis)
    assert set(hourly["kind"]) <= {"success", "failure / invalid user"}
    assert hourly["events"].sum() == analysis.events["event_type"].isin(views.AUTH_TYPES).sum()
    scores = views.anomaly_scores(analysis)
    assert len(scores) == len(analysis.windows)
    assert set(scores["status"]) == {"flagged", "normal"}


# --- Headless Streamlit run ---------------------------------------------------

pytest.importorskip("streamlit")


class FakeClient:
    model = "fake-model"

    def __init__(self, script):
        self.script = list(script)

    def chat(self, messages, tools=None):
        return self.script.pop(0)


@pytest.fixture
def app(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.chdir(tmp_path)  # manifest and audit log go to a scratch directory
    return AppTest.from_file(str(APP), default_timeout=60)


def test_app_renders_sample_without_ollama(app):
    app.session_state["chat_client"] = FakeClient([])
    app.run()
    assert not app.exception
    assert [t.label for t in app.tabs] == ["Overview", "Findings", "Timeline", "Ask Marlowe"]
    assert any(m.label == "Flagged windows" for m in app.metric)
    assert "Synthetic sample" in app.radio[0].value


def test_app_chat_shows_grounding_badge(app, analysis):
    tools_line = int(views.finding_lines(analysis, 0, 1)["line"][0])
    script = [
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"function": {"name": "get_finding", "arguments": {"finding_id": "F1"}}}
            ],
        },
        {"role": "assistant", "content": f"F1 is the top finding [line {tools_line}]."},
    ]
    app.session_state["chat_client"] = FakeClient(script)
    app.run()
    app.chat_input[0].set_value("What is the top finding?").run()
    assert not app.exception
    assert any("top finding" in m.value for m in app.markdown)
    assert any("Grounding check passed" in s.value for s in app.success)
    assert (Path("data/processed/assistant_audit.jsonl")).exists()


def test_smoke_loader_escapes_message_and_respects_reduced_motion():
    from marlowe.webapp import effects

    html = effects.smoke_loader("<b>working</b>")
    assert "&lt;b&gt;working&lt;/b&gt;" in html and "<b>" not in html
    for css in (effects.SMOKE_LOADER, effects.DRIFTING_SMOKE):
        assert "prefers-reduced-motion" in css
    assert "pointer-events:none" in effects.DRIFTING_SMOKE


def test_noir_toggle_switches_the_persona(app):
    app.session_state["chat_client"] = FakeClient([])
    app.run()
    assert app.session_state["analyst"].persona is True
    next(t for t in app.toggle if t.label == "Noir voice").set_value(False).run()
    assert not app.exception
    assert app.session_state["analyst"].persona is False


def test_newest_first_keeps_each_question_with_its_answer():
    chat = [
        {"role": "user", "text": "q1"},
        {"role": "assistant", "text": "a1"},
        {"role": "user", "text": "q2"},
        {"role": "assistant", "text": "a2"},
    ]
    turns = views.newest_first(chat)
    assert [[e["text"] for e in t] for t in turns] == [["q2", "a2"], ["q1", "a1"]]
