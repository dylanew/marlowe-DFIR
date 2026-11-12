"""Marlowe web app (Streamlit).

Run with ``marlowe web`` or ``streamlit run src/marlowe/webapp/app.py``.

Streamlit re-runs this whole script on every click, top to bottom. Two things
keep that cheap and correct:

* the analysis is cached by (evidence file, year, timezone), so it only runs
  when the evidence or its settings change;
* the assistant (``Analyst``) lives in ``st.session_state`` and is rebuilt
  only when the evidence changes, so a conversation survives re-runs.

All data shaping lives in ``views.py`` (tested without Streamlit). This file
only lays out widgets.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import altair as alt
import streamlit as st

from marlowe.assistant import AnalysisTools, Analyst, OllamaClient, OllamaError
from marlowe.assistant.ollama import DEFAULT_MODEL, DEFAULT_URL
from marlowe.pipeline import AnalysisResult, analyse_auth_log
from marlowe.synthetic import generate_auth_log
from marlowe.webapp import effects, views

REPO_ROOT = Path(__file__).resolve().parents[3]
DATA = Path("data")
MANIFEST = DATA / "processed" / "evidence.manifest.jsonl"
AUDIT = DATA / "processed" / "assistant_audit.jsonl"
UPLOADS = DATA / "raw" / "uploads"

st.set_page_config(page_title="Marlowe DFIR", page_icon="🔎", layout="wide")


# --- Evidence and analysis ---------------------------------------------------


def sample_paths() -> tuple[Path, Path]:
    """The bundled synthetic sample, or a freshly generated one if not running from the repo."""
    sample = REPO_ROOT / "data" / "sample"
    if not (sample / "auth.log").exists():
        sample = Path(tempfile.gettempdir()) / "marlowe_sample"
        if not (sample / "auth.log").exists():
            generate_auth_log().write(sample / "auth.log", sample / "auth_labels.csv")
    return sample / "auth.log", sample / "auth_labels.csv"


@st.cache_resource(show_spinner="Hashing evidence, parsing and scoring windows...")
def run_analysis(log: str, year: int, tz: str, labels: str | None) -> AnalysisResult:
    return analyse_auth_log(log, manifest_path=MANIFEST, year=year, tz=tz, labels_path=labels)


def get_client(model: str, url: str):
    """The chat client. Tests put a fake one in session state; normally it is Ollama."""
    return st.session_state.get("chat_client") or OllamaClient(model=model, base_url=url)


def installed_models(url: str) -> list[str] | None:
    if "chat_client" in st.session_state:
        return [st.session_state["chat_client"].model]
    try:
        return OllamaClient(base_url=url, timeout=3).list_models()
    except OllamaError:
        return None


# --- Sidebar ----------------------------------------------------------------

with st.sidebar:
    st.title("🔎 Marlowe")
    st.caption("Local, explainable anomaly detection for Linux SSH logs.")

    source = st.radio("Evidence", ["Synthetic sample", "Upload auth.log"])
    labels: Path | None = None
    if source == "Synthetic sample":
        log_path, labels = sample_paths()
        st.caption("14 days of generated activity with labelled attacks, so detection is scored.")
    else:
        upload = st.file_uploader("auth.log", type=None)
        if upload is None:
            st.info("Upload an auth.log to analyse it. Nothing leaves this machine.")
            st.stop()
        log_path = views.save_upload(upload.getvalue(), upload.name, UPLOADS)

    year = st.number_input(
        "Year of first log line",
        1990,
        2100,
        2026,
        help=("Syslog timestamps have no year, so it has to be supplied."),
    )
    tz = st.text_input("Host timezone", "UTC", help="Timezone of the logging host's clock.")

    st.divider()
    ollama_url = st.text_input("Ollama URL", DEFAULT_URL)
    models = installed_models(ollama_url)
    if models is None:
        st.warning("Ollama is not reachable, so Ask Marlowe is off. Start it with `ollama serve`.")
        model = DEFAULT_MODEL
    elif not models:
        st.warning(f"No models installed. Run `ollama pull {DEFAULT_MODEL}`.")
        model = DEFAULT_MODEL
    else:
        default = next((i for i, m in enumerate(models) if m.startswith(DEFAULT_MODEL)), 0)
        model = st.selectbox("Model", models, index=default)

    st.divider()
    noir = st.toggle(
        "Noir voice",
        value=True,
        help="Marlowe answers in the voice of a 1930s private eye. Tone only: "
        "evidence, citations and the grounding check are unchanged.",
    )
    atmosphere = st.toggle("Atmosphere", value=True, help="Occasional drifting smoke.")

if atmosphere:
    st.markdown(effects.DRIFTING_SMOKE, unsafe_allow_html=True)

try:
    result = run_analysis(str(log_path), int(year), tz, str(labels) if labels else None)
except Exception as exc:  # shown to the user rather than a stack trace
    st.error(f"Could not analyse this file: {exc}")
    st.stop()

evidence = result.evidence
st.title("Investigation overview")
st.caption(
    f"Evidence `{evidence.evidence_id}` · SHA-256 `{evidence.sha256}` · "
    f"{evidence.size_bytes:,} bytes"
)

overview, findings_tab, timeline, ask = st.tabs(["Overview", "Findings", "Timeline", "Ask Marlowe"])

# --- Overview ----------------------------------------------------------------

with overview:
    stats = views.overview_stats(result)
    c = st.columns(5)
    unparsed = f"{stats['unparsed']} unparsed, kept as-is"
    c[0].metric("Log lines", f"{stats['lines']:,}", help=unparsed)
    c[1].metric("Source IPs", stats["source_ips"])
    c[2].metric("Usernames", stats["users"])
    c[3].metric("Flagged windows", stats["findings"])
    c[4].metric("Time span (days)", f"{(stats['end'] - stats['start']).days + 1}")
    st.caption(
        f"{stats['start']:%Y-%m-%d %H:%M} to {stats['end']:%Y-%m-%d %H:%M} UTC. "
        f"Models were trained on activity before {result.cutoff:%Y-%m-%d %H:%M} UTC "
        f"({len(result.train_windows)} windows) and score the {len(result.windows)} "
        "windows after it."
    )

    left, right = st.columns([1, 2])
    left.subheader("Parsed events")
    left.dataframe(stats["event_counts"], hide_index=True, width="stretch")

    if result.metrics:
        right.subheader("How well the detectors did")
        right.caption("Scored against the sample's ground-truth labels, on the test period only.")
        right.dataframe(
            [
                {
                    "detector": name,
                    "precision": round(m["precision"], 2),
                    "recall": round(m["recall"], 2),
                    "F1": round(m["f1"], 2),
                    "TP": m["tp"],
                    "FP": m["fp"],
                    "FN": m["fn"],
                }
                for name, m in result.metrics.items()
            ],
            hide_index=True,
            width="stretch",
        )
        right.dataframe(result.incidents, hide_index=True, width="stretch")
    else:
        right.info("No ground-truth labels for this evidence, so detection can't be scored.")

# --- Findings ----------------------------------------------------------------

with findings_tab:
    table = views.findings_table(result)
    st.subheader(f"{len(table)} flagged windows")
    st.caption(
        "Each row is one source IP in one 10-minute window that the rules, the Isolation "
        "Forest, or both flagged. A flag is a lead to investigate, not proof of an attack."
    )
    if table.empty:
        st.success("Nothing was flagged in the test period.")
    else:
        st.dataframe(table, hide_index=True, width="stretch")
        choice = st.selectbox(
            "Inspect the evidence behind a finding",
            range(len(table)),
            format_func=lambda i: (
                f"{table.at[i, 'finding']}: {table.at[i, 'source IP']} "
                f"at {table.at[i, 'window (UTC)']}"
            ),
        )
        st.dataframe(views.finding_lines(result, choice), hide_index=True, width="stretch")

# --- Timeline ----------------------------------------------------------------

with timeline:
    st.subheader("Authentication activity per hour")
    hourly = views.hourly_activity(result)
    st.altair_chart(
        alt.Chart(hourly)
        .mark_line()
        .encode(
            x=alt.X("timestamp_utc:T", title="time (UTC)", axis=alt.Axis(format="%d %b")),
            y=alt.Y("events:Q", title="events per hour"),
            color=alt.Color(
                "kind:N",
                title=None,
                scale=alt.Scale(
                    domain=["success", "failure / invalid user"],
                    range=[views.COLOURS["success"], views.COLOURS["failure"]],
                ),
                legend=alt.Legend(orient="top"),
            ),
            tooltip=["timestamp_utc:T", "kind:N", "events:Q"],
        )
        .properties(height=260),
        width="stretch",
    )

    st.subheader("Anomaly score of every window in the test period")
    st.caption("Higher means more unusual to the Isolation Forest. Hover for the source IP.")
    scores = views.anomaly_scores(result)
    st.altair_chart(
        alt.Chart(scores)
        .mark_circle(opacity=0.7)
        .encode(
            x=alt.X("window_start:T", title="window start (UTC)"),
            y=alt.Y("anomaly score:Q"),
            color=alt.Color(
                "status:N",
                scale=alt.Scale(
                    domain=["normal", "flagged"],
                    range=[views.COLOURS["normal"], views.COLOURS["flagged"]],
                ),
                legend=alt.Legend(orient="top", title=None),
            ),
            size=alt.Size("failed:Q", title="failed logins", legend=None),
            tooltip=["src_ip:N", "window_start:T", "anomaly score:Q", "failed:Q", "status:N"],
        )
        .properties(height=300),
        width="stretch",
    )

# --- Ask Marlowe -------------------------------------------------------------

with ask:
    st.caption(
        "Marlowe is a local LLM that can only see this evidence through read-only tools. "
        "Every answer is checked: cited lines must be ones the tools returned, and IPs and "
        f"hashes must exist in the evidence. All answers are logged to `{AUDIT}`."
    )
    if models is None and "chat_client" not in st.session_state:
        st.info("Start Ollama and reload the page to ask questions.")
    else:
        key = (evidence.evidence_id, model, noir)
        if st.session_state.get("analyst_key") != key:
            st.session_state.analyst = Analyst(
                get_client(model, ollama_url),
                AnalysisTools(result),
                audit_path=AUDIT,
                persona=noir,
            )
            st.session_state.analyst_key = key
            st.session_state.chat = []

        def show(entry: dict) -> None:
            with st.chat_message(entry["role"]):
                st.markdown(entry["text"])
                if entry["role"] == "assistant":
                    if entry["passed"]:
                        st.success(entry["check"], icon="✅")
                    else:
                        st.error(entry["check"], icon="⚠️")
                    if entry["retried"]:
                        st.caption("The first answer failed the evidence check and was corrected.")
                    with st.expander(f"Tools used ({len(entry['tools'])})"):
                        st.code("\n".join(entry["tools"]) or "none", language=None)

        for entry in st.session_state.chat:
            show(entry)

        prompt = "Ask about the evidence, e.g. 'Was there a brute-force attack?'"
        if question := st.chat_input(prompt):
            st.session_state.chat.append({"role": "user", "text": question})
            show(st.session_state.chat[-1])
            waiting = st.empty()
            waiting.markdown(
                effects.smoke_loader("Marlowe is examining the evidence..."),
                unsafe_allow_html=True,
            )
            try:
                a = st.session_state.analyst.ask(question)
            except OllamaError as exc:
                waiting.empty()
                st.error(str(exc))
                st.stop()
            waiting.empty()
            entry = {
                "role": "assistant",
                "text": a.text,
                "passed": a.verification.passed,
                "check": a.verification.summary(),
                "retried": bool(a.retries),
                "tools": [f"{c.name}({json.dumps(c.arguments)})" for c in a.tool_calls],
            }
            st.session_state.chat.append(entry)
            show(entry)
