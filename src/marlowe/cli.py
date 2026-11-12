"""Command-line interface.

marlowe generate --out data/sample        # write a synthetic auth.log + labels
marlowe analyse data/sample/auth.log --year 2026 --labels data/sample/auth_labels.csv
marlowe chat data/sample/auth.log --year 2026      # ask Marlowe (needs Ollama running)
marlowe web                                        # the web app (needs the `web` extra)
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

import pandas as pd

from marlowe.assistant.ollama import DEFAULT_MODEL, DEFAULT_URL
from marlowe.assistant.prompts import DEFAULT_PERSONA_LEVEL, PERSONA_LEVELS
from marlowe.pipeline import analyse_auth_log
from marlowe.synthetic import generate_auth_log


def _cmd_generate(args: argparse.Namespace) -> None:
    out = Path(args.out)
    log = generate_auth_log(
        start=datetime.fromisoformat(args.start), days=args.days, seed=args.seed
    )
    log.write(out / "auth.log", out / "auth_labels.csv")
    print(f"Wrote {len(log.events)} lines to {out / 'auth.log'} (labels: auth_labels.csv)")


def _fmt(m: dict) -> str:
    s = f"precision {m['precision']:.2f}  recall {m['recall']:.2f}  F1 {m['f1']:.2f}  "
    s += f"(TP {m['tp']}, FP {m['fp']}, FN {m['fn']})"
    if "average_precision" in m:
        s += f"  AP {m['average_precision']:.2f}"
    return s


def _cmd_analyse(args: argparse.Namespace) -> None:
    result = analyse_auth_log(
        args.log,
        manifest_path=args.manifest,
        year=args.year,
        tz=args.tz,
        labels_path=args.labels,
        window=args.window,
        train_fraction=args.train_fraction,
        contamination=args.contamination,
    )
    ev = result.evidence
    print(f"Evidence {ev.evidence_id}  sha256={ev.sha256}  ({ev.size_bytes} bytes)")
    print("\nParsed events:")
    print(result.parse_summary.to_string())
    print(
        f"\nWindows: {len(result.train_windows)} train / {len(result.windows)} test "
        f"(cutoff {result.cutoff:%Y-%m-%d %H:%M} UTC)"
    )

    if result.metrics:
        print("\nTest-period evaluation (window level):")
        for name, m in result.metrics.items():
            print(f"  {name:<17} {_fmt(m)}")
        print("\nIncidents in the test period:")
        print(result.incidents.to_string(index=False))

    findings = result.findings()
    print(f"\n{len(findings)} flagged windows. Top 10:")
    with pd.option_context("display.max_colwidth", 80, "display.width", 200):
        show = findings.head(10).copy()
        show["lines"] = show["line_nos"].map(lambda n: f"{n[0]}-{n[-1]}" if len(n) > 1 else n[0])
        print(show[["src_ip", "window_start", "rule_reasons", "if_reasons", "lines"]].to_string())

    if args.findings:
        Path(args.findings).parent.mkdir(parents=True, exist_ok=True)
        findings.to_csv(args.findings, index=False)
        print(f"\nAll findings written to {args.findings}")


def _cmd_chat(args: argparse.Namespace) -> None:
    # Imported here so `marlowe generate/analyse` work without touching the assistant.
    from marlowe.assistant import AnalysisTools, Analyst, OllamaClient, OllamaError

    client = OllamaClient(model=args.model, base_url=args.ollama_url)
    try:
        available = client.list_models()
    except OllamaError as exc:
        raise SystemExit(str(exc)) from exc
    if args.model not in available and f"{args.model}:latest" not in available:
        raise SystemExit(
            f"Model '{args.model}' is not installed. Run `ollama pull {args.model}`. "
            f"Installed: {', '.join(available) or 'none'}"
        )

    print("Running analysis...")
    result = analyse_auth_log(
        args.log, manifest_path=args.manifest, year=args.year, tz=args.tz, window=args.window
    )
    analyst = Analyst(client, AnalysisTools(result), audit_path=args.audit, persona=args.persona)
    print(
        f"Evidence {result.evidence.evidence_id} loaded. Model: {args.model}. "
        f"Every answer is logged to {args.audit}."
    )

    def answer(question: str) -> None:
        try:
            a = analyst.ask(question)
        except OllamaError as exc:
            print(f"[error] {exc}")
            return
        print(f"\n{a.text}\n")
        calls = ", ".join(f"{c.name}({json.dumps(c.arguments)})" for c in a.tool_calls)
        print(f"[tools: {calls or 'none'}]")
        if a.retries:
            print("[first answer failed the evidence check; the model was asked to fix it]")
        print(f"[{a.verification.summary()}]\n")

    if args.question:
        answer(args.question)
        return
    print("Ask a question about the evidence (blank line or Ctrl-D to quit).")
    while True:
        try:
            question = input("you> ").strip()
        except EOFError:
            break
        if not question:
            break
        answer(question)


def _cmd_web(args: argparse.Namespace) -> None:
    import importlib.util
    import subprocess
    import sys

    if importlib.util.find_spec("streamlit") is None:
        raise SystemExit('The web app needs Streamlit. Run: pip install -e ".[web]"')
    app = Path(__file__).parent / "webapp" / "app.py"
    cmd = [sys.executable, "-m", "streamlit", "run", str(app), "--server.port", str(args.port)]
    # Bind to this machine only by default: the app shows raw evidence.
    cmd += ["--server.address", args.address, "--browser.gatherUsageStats", "false"]
    raise SystemExit(subprocess.call(cmd))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="marlowe", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="Generate a synthetic labelled auth.log")
    gen.add_argument("--out", default="data/sample")
    gen.add_argument("--start", default="2026-10-05")
    gen.add_argument("--days", type=int, default=14)
    gen.add_argument("--seed", type=int, default=42)
    gen.set_defaults(func=_cmd_generate)

    ana = sub.add_parser("analyse", help="Analyse an auth.log for anomalies")
    ana.add_argument("log")
    ana.add_argument("--year", type=int, required=True, help="year of the first log line")
    ana.add_argument("--tz", default="UTC", help="timezone of the logging host's clock")
    ana.add_argument("--labels", help="ground-truth labels CSV (enables evaluation)")
    ana.add_argument("--manifest", default="data/processed/evidence.manifest.jsonl")
    ana.add_argument("--findings", default="data/processed/findings.csv")
    ana.add_argument("--window", default="10min")
    ana.add_argument("--train-fraction", type=float, default=0.6)
    ana.add_argument("--contamination", type=float, default=0.02)
    ana.set_defaults(func=_cmd_analyse)

    chat = sub.add_parser("chat", help="Ask Marlowe (local LLM via Ollama) about an auth.log")
    chat.add_argument("log")
    chat.add_argument("--year", type=int, required=True)
    chat.add_argument("--tz", default="UTC")
    chat.add_argument("--question", "-q", help="ask one question and exit")
    chat.add_argument("--model", default=DEFAULT_MODEL)
    chat.add_argument("--ollama-url", default=DEFAULT_URL)
    chat.add_argument("--manifest", default="data/processed/evidence.manifest.jsonl")
    chat.add_argument("--audit", default="data/processed/assistant_audit.jsonl")
    chat.add_argument("--window", default="10min")
    voice = chat.add_mutually_exclusive_group()
    voice.add_argument(
        "--persona",
        type=int,
        choices=sorted(PERSONA_LEVELS),
        default=0,
        metavar="LEVEL",
        help="personality slider, tone only: "
        + ", ".join(f"{n} {name}" for n, name in PERSONA_LEVELS.items())
        + " (default 0)",
    )
    voice.add_argument(
        "--noir",
        dest="persona",
        action="store_const",
        const=DEFAULT_PERSONA_LEVEL,
        help=f"shorthand for --persona {DEFAULT_PERSONA_LEVEL}",
    )
    chat.set_defaults(func=_cmd_chat)

    web = sub.add_parser("web", help="Open the Marlowe web app in your browser")
    web.add_argument("--port", type=int, default=8501)
    web.add_argument("--address", default="localhost")
    web.set_defaults(func=_cmd_web)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
