"""Benchmark local Ollama models as Marlowe's analyst, across personality levels.

Run from the repository root, with Ollama running and the models pulled:

    # compare models (plain voice)
    python scripts/benchmark_models.py llama3.1:8b qwen2.5:7b

    # the personality slider: same questions at every level, 0 (plain) to 4 (full noir)
    python scripts/benchmark_models.py llama3.1:8b --levels 0 1 2 3 4

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
from marlowe.assistant.prompts import DEFAULT_PERSONA_LEVEL, PERSONA_LEVELS
from marlowe.evaluation.persona import PersonaBenchmark, summarise_by_level
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
    args = parser.parse_args()

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

    def report(row: dict) -> None:
        if row["error"]:
            print(f"{row['model']:<16} L{row['persona_level']}  ERROR {row['error']}")
            return
        print(
            f"{row['model']:<16} L{row['persona_level']} {row['seconds']:>6}s  "
            f"first_try={row['first_attempt_grounded']!s:<5} grounded={row['grounded']!s:<5} "
            f"correct={row['correct']!s:<5} voice={row['voice_score']:<5}  {row['question'][:50]}"
        )

    frames = []
    for model in args.models:
        client = OllamaClient(model=model, temperature=args.temperature)

        def make_analyst(level: int, client: OllamaClient = client) -> Analyst:
            # A fresh Analyst per question, so earlier answers can't help later ones.
            return Analyst(
                client,
                AnalysisTools(result),
                max_retries=args.retries,
                audit_path=args.audit,
                persona=level,
            )

        bench = PersonaBenchmark(make_analyst, facts, on_row=report)
        frames.append(
            bench.run(args.levels, repeats=args.repeats, model=model, temperature=args.temperature)
        )

    df = pd.concat(frames, ignore_index=True)
    df["persona_name"] = df["persona_level"].map(PERSONA_LEVELS)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.out, index=False)

    summary = summarise_by_level(df, by=("model", "persona_level"))
    with pd.option_context("display.width", 200, "display.max_columns", 30):
        print("\n" + summary.to_string(index=False))
    print(f"\nPer-question results: {args.out}")
    print(f"Full answers and tool calls: {args.audit}")
    ok = df[df["error"] == ""]
    for _, row in ok[~ok["grounded"].astype(bool)].iterrows():
        print(f"\nFAILED [{row['model']} L{row['persona_level']}] {row['question']}")
        print(f"  tools: {row['tools_used'] or 'none'}")
        print(f"  {row['grounding']}")


if __name__ == "__main__":
    main()
