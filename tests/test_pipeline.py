from marlowe.cli import main
from marlowe.pipeline import analyse_auth_log
from marlowe.synthetic import generate_auth_log


def test_end_to_end_on_synthetic_data(tmp_path):
    generate_auth_log().write(tmp_path / "auth.log", tmp_path / "labels.csv")
    result = analyse_auth_log(
        tmp_path / "auth.log",
        tmp_path / "manifest.jsonl",
        year=2026,
        labels_path=tmp_path / "labels.csv",
    )
    assert (result.events["event_type"] != "unparsed").all()
    assert result.train_windows["window_start"].max() < result.windows["window_start"].min()
    assert set(result.metrics) == {"rules", "isolation_forest", "either"}
    # Loose sanity bounds rather than exact numbers, so the test documents
    # expected behaviour without freezing every detail of the synthetic data.
    assert result.metrics["either"]["recall"] >= 0.5
    assert result.metrics["isolation_forest"]["average_precision"] >= 0.5
    findings = result.findings()
    assert len(findings) > 0
    assert findings["line_nos"].map(len).min() >= 1
    assert (findings["evidence_id"] == result.evidence.evidence_id).all()


def test_cli_generate_and_analyse(tmp_path, capsys):
    main(["generate", "--out", str(tmp_path), "--days", "14"])
    main(
        [
            "analyse",
            str(tmp_path / "auth.log"),
            "--year",
            "2026",
            "--labels",
            str(tmp_path / "auth_labels.csv"),
            "--manifest",
            str(tmp_path / "m.jsonl"),
            "--findings",
            str(tmp_path / "findings.csv"),
        ]
    )
    out = capsys.readouterr().out
    assert "Test-period evaluation" in out
    assert (tmp_path / "findings.csv").exists()
