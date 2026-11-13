"""Benchmark local Ollama models as Marlowe's analyst, across personality levels.

Run from the repository root, with Ollama running and the models pulled:

    # compare models (plain voice)
    python scripts/benchmark_models.py llama3.1:8b qwen2.5:7b

    # the personality slider: same questions at every level, 0 (plain) to 4 (full noir)
    python scripts/benchmark_models.py llama3.1:8b --levels 0 1 2 3 4

    # quicker: a subset of questions (numbered from 1; --list-questions shows them)
    python scripts/benchmark_models.py llama3.1:8b --levels 0 2 4 --questions 1 2 6 8

    # carry on after stopping it (skips answers already in --out)
    python scripts/benchmark_models.py llama3.1:8b --levels 0 1 2 3 4 --resume

    # rebuild the results from the audit log without asking the model again
    python scripts/benchmark_models.py llama3.1:8b --from-audit

How long it takes: on an M4 MacBook Air (16 GB) with llama3.1:8b, answers take
20 s to 5 min each, around 2.5 min on average, so all 8 questions at all 5
levels (40 answers) take 1.5 to 2 hours. The results table is rewritten after
every answer, so stopping early loses nothing.

For every model, slider level and question it records latency, tool calls,
whether it looked at raw log lines, whether the grounding check passed (first
try and after the retry), whether the answer got known facts right, and how
much "voice" the answer has (see ``marlowe.evaluation.persona``). Results go to
a CSV, every full answer goes to an audit log, and a summary table with 95%
intervals is printed.

Why benchmark rather than pick the biggest model? On a 16 GB Mac, an 8B
model at 4-bit quantisation fits comfortably and anything much larger will
swap. Within that budget, models differ a lot in how reliably they call
tools and cite evidence, and only measuring shows which works best here.
The same goes for the persona: it should cost nothing in grounding, but
that has to be shown, not assumed.
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

import pandas as pd

from marlowe.assistant import AnalysisTools, Analyst, OllamaClient
from marlowe.assistant.prompts import DEFAULT_PERSONA_LEVEL, PERSONA_LEVELS, PERSONA_VERSION
from marlowe.evaluation.persona import (
    QUESTIONS,
    PersonaBenchmark,
    done_keys,
    rows_from_audit,
    summarise_by_level,
)
from marlowe.pipeline import analyse_auth_log
from marlowe.synthetic import generate_auth_log


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("models", nargs="+")
    parser.add_argument("--out", default="data/processed/model_benchmark.csv")
    parser.add_argument(
        "--audit",
        default="data/processed/benchmark_audit.jsonl",
        help="full record of every answer (tool calls, both attempts, grounding)",
    )
    parser.add_argument(
        "--retries", type=int, default=1, help="grounding retries per answer (0 = off)"
    )
    levels = parser.add_mutually_exclusive_group()
    levels.add_argument(
        "--levels",
        type=int,
        nargs="+",
        choices=sorted(PERSONA_LEVELS),
        default=[0],
        metavar="LEVEL",
        help="personality slider levels to benchmark: "
        + ", ".join(f"{n} {name}" for n, name in PERSONA_LEVELS.items())
        + " (default 0)",
    )
    levels.add_argument(
        "--noir",
        dest="levels",
        action="store_const",
        const=[DEFAULT_PERSONA_LEVEL],
        help=f"shorthand for --levels {DEFAULT_PERSONA_LEVEL}",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=1,
        help="ask each question this many times per level. Only useful with "
        "--temperature above 0: at 0 the answers repeat almost exactly",
    )
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument(
        "--questions",
        type=int,
        nargs="+",
        metavar="N",
        help="ask only these questions, numbered from 1 (see --list-questions)",
    )
    parser.add_argument(
        "--list-questions", action="store_true", help="print the numbered questions and exit"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=600,
        help="seconds to wait for one model reply before giving up (default 600)",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=1024,
        help="cap on tokens in one model reply (default 1024), so a reply stuck in a "
        "loop ends instead of timing out",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="keep the answers already in --out and ask only the missing or failed ones",
    )
    parser.add_argument(
        "--from-audit",
        action="store_true",
        help="don't ask the model: rebuild --out from the answers in --audit",
    )
    parser.add_argument(
        "--persona-version",
        default=PERSONA_VERSION,
        help="with --from-audit, only voiced answers from this persona wording "
        f"(default {PERSONA_VERSION}, the current one; 'any' for all)",
    )
    parser.add_argument(
        "--since",
        help="with --from-audit, only answers logged at or after this UTC time, "
        "e.g. 2026-11-12T21:00",
    )
    args = parser.parse_args()
    if args.persona_version == "any":
        args.persona_version = None

    if args.list_questions:
        for i, q in enumerate(QUESTIONS, 1):
            print(f"{i}. [{q.kind}] {q.text}")
        return
    try:
        questions = [QUESTIONS[i - 1] for i in args.questions] if args.questions else QUESTIONS
    except IndexError:
        parser.error(f"--questions are numbered 1 to {len(QUESTIONS)}")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        generate_auth_log().write(tmp / "auth.log", tmp / "labels.csv")
        result = analyse_auth_log(tmp / "auth.log", tmp / "manifest.jsonl", year=2026)

    # Ground truth for the correctness checks: the top finding's IP, and the
    # account it got into (the synthetic brute force succeeds as root).
    tools = AnalysisTools(result)
    top_ip = tools.findings.iloc[0]["src_ip"]
    logins = tools.successful_logins(top_ip)
    facts = {"top_ip": top_ip, "top_user": logins[0]["user"] if logins else top_ip}

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.from_audit:
        df = rows_from_audit(
            args.audit, facts, questions, since=args.since, persona_version=args.persona_version
        )
        df = df[df["model"].isin(args.models) & df["persona_level"].isin(args.levels)]
        if df.empty:
            raise SystemExit(f"No slider answers for those models and levels in {args.audit}")
        _finish(df, out, args.audit)
        return

    earlier = pd.DataFrame()
    if args.resume and out.exists():
        # Read "error" as text: when no answer failed it is all blank, which
        # pandas would otherwise read as a float column of NaN.
        earlier = pd.read_csv(out, converters={"error": str})
        earlier = earlier[earlier["error"] == ""]  # failed answers are asked again
        print(f"Resuming: {len(earlier)} answers already in {out}")
    rows: list[dict] = earlier.to_dict("records")

    def report(row: dict) -> None:
        # Rewrite the whole table after every answer, so stopping loses nothing.
        rows.append(row)
        pd.DataFrame(rows).to_csv(out, index=False)
        if row["error"]:
            print(f"{row['model']:<16} L{row['persona_level']}  ERROR {row['error']}")
            return
        print(
            f"{row['model']:<16} L{row['persona_level']} {row['seconds']:>6}s  "
            f"first_try={row['first_attempt_grounded']!s:<5} grounded={row['grounded']!s:<5} "
            f"correct={row['correct']!s:<5} voice={row['voice_score']:<5}  {row['question'][:50]}"
        )

    for model in args.models:
        client = OllamaClient(
            model=model,
            temperature=args.temperature,
            timeout=args.timeout,
            max_tokens=args.max_tokens,
        )

        def make_analyst(level: int, client: OllamaClient = client) -> Analyst:
            # A fresh Analyst per question, so earlier answers can't help later ones.
            return Analyst(
                client,
                AnalysisTools(result),
                max_retries=args.retries,
                audit_path=args.audit,
                persona=level,
            )

        bench = PersonaBenchmark(
            make_analyst, facts, questions=questions, on_row=report, done=done_keys(earlier)
        )
        bench.run(
            args.levels,
            repeats=args.repeats,
            model=model,
            temperature=args.temperature,
            persona_version=PERSONA_VERSION,
        )

    _finish(pd.DataFrame(rows), out, args.audit)


def _finish(df: pd.DataFrame, out: Path, audit: str) -> None:
    """Save the table and print the summary and the failures."""
    df["persona_name"] = df["persona_level"].astype(int).map(PERSONA_LEVELS)
    df.to_csv(out, index=False)

    summary = summarise_by_level(df, by=("model", "persona_level"))
    with pd.option_context("display.width", 200, "display.max_columns", 30):
        print("\n" + summary.to_string(index=False))
    print(f"\nPer-question results: {out}")
    print(f"Full answers and tool calls: {audit}")
    ok = df[df["error"] == ""]
    if ok.empty:
        return
    for _, row in ok[~ok["grounded"].astype(bool)].iterrows():
        print(f"\nFAILED [{row['model']} L{row['persona_level']}] {row['question']}")
        print(f"  tools: {row['tools_used'] or 'none'}")
        print(f"  {row['grounding']}")


if __name__ == "__main__":
    main()
