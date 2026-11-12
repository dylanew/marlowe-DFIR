"""Benchmark local Ollama models as Marlowe's analyst on the synthetic dataset.

Run from the repository root, with Ollama running and the models pulled:

    python scripts/benchmark_models.py llama3.1:8b qwen2.5:7b mistral-nemo

For every model and question it records latency, the number of tool calls,
whether it fetched raw log lines (not just computed summaries), whether the
grounding check passed, and whether the answer names the IP
behind the top finding. Results go to data/processed/model_benchmark.csv,
and a summary table is printed.

Why benchmark rather than pick the biggest model? On a 16 GB Mac, an 8B
model at 4-bit quantisation fits comfortably and anything much larger will
swap. Within that budget, models differ a lot in how reliably they call
tools and cite evidence, and only measuring shows which works best here.
"""

from __future__ import annotations

import argparse
import tempfile
import time
from pathlib import Path

import pandas as pd

from marlowe.assistant import AnalysisTools, Analyst, OllamaClient
from marlowe.pipeline import analyse_auth_log
from marlowe.synthetic import generate_auth_log

QUESTIONS = [
    "Give me an overview of this evidence and the most serious finding.",
    "Which source IP looks most like a brute-force attack, and did it ever log in successfully?",
    "Are there any successful logins at unusual hours from new addresses? List them.",
    "Is finding F2 likely to be malicious? Show me the log lines that support your view.",
    "Which flagged findings could plausibly be benign, and why?",
]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("models", nargs="+")
    parser.add_argument("--out", default="data/processed/model_benchmark.csv")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        generate_auth_log().write(tmp / "auth.log", tmp / "labels.csv")
        result = analyse_auth_log(tmp / "auth.log", tmp / "manifest.jsonl", year=2026)

    top_ip = AnalysisTools(result).findings.iloc[0]["src_ip"]
    rows = []
    for model in args.models:
        client = OllamaClient(model=model)
        for question in QUESTIONS:
            # A fresh Analyst per question, so earlier answers can't help later ones.
            analyst = Analyst(client, AnalysisTools(result))
            start = time.perf_counter()
            try:
                answer = analyst.ask(question)
            except Exception as exc:  # report and carry on with the next question
                rows.append({"model": model, "question": question, "error": str(exc)})
                continue
            rows.append(
                {
                    "model": model,
                    "question": question,
                    "seconds": round(time.perf_counter() - start, 1),
                    "tool_calls": len(answer.tool_calls),
                    "distinct_tools": len({c.name for c in answer.tool_calls}),
                    # Did it look at the raw evidence, or only at computed summaries?
                    "fetched_raw_lines": any(c.name == "get_log_lines" for c in answer.tool_calls),
                    "grounded": answer.verification.passed,
                    "cited_lines": len(answer.verification.cited_lines),
                    "hit_step_limit": answer.hit_step_limit,
                    "mentions_top_ip": top_ip in answer.text,
                    "error": "",
                }
            )
            print(f"{model:<20} {rows[-1]['seconds']:>6}s  grounded={answer.verification.passed}")

    df = pd.DataFrame(rows)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.out, index=False)

    ok = df[df["error"] == ""]
    summary = ok.groupby("model").agg(
        median_seconds=("seconds", "median"),
        mean_tool_calls=("tool_calls", "mean"),
        raw_lines_rate=("fetched_raw_lines", "mean"),
        grounded_rate=("grounded", "mean"),
        step_limit_rate=("hit_step_limit", "mean"),
    )
    summary["errors"] = df.groupby("model")["error"].apply(lambda e: int((e != "").sum()))
    print("\n" + summary.round(2).to_string())
    print(f"\nPer-question results: {args.out}")


if __name__ == "__main__":
    main()
