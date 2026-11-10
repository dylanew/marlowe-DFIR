import hashlib

import pytest

from marlowe.forensics import (
    EvidenceRecord,
    load_manifest,
    register_evidence,
    sha256_file,
    verify_evidence,
)


@pytest.fixture
def evidence_file(tmp_path):
    path = tmp_path / "auth.log"
    path.write_bytes(b"Nov 10 09:00:01 host sshd[1]: Accepted password for alice\n")
    return path


def test_sha256_matches_hashlib(evidence_file):
    expected = hashlib.sha256(evidence_file.read_bytes()).hexdigest()
    assert sha256_file(evidence_file) == expected


def test_sha256_handles_files_larger_than_one_chunk(tmp_path):
    path = tmp_path / "big.bin"
    data = b"x" * (3 * 1024 * 1024 + 7)  # spans several 1 MiB chunks
    path.write_bytes(data)
    assert sha256_file(path) == hashlib.sha256(data).hexdigest()


def test_register_writes_manifest_entry(evidence_file, tmp_path):
    manifest = tmp_path / "case.manifest.jsonl"
    record = register_evidence(evidence_file, manifest, notes="test import")

    assert record.sha256 == sha256_file(evidence_file)
    assert record.evidence_id == record.sha256[:12]
    assert record.size_bytes == evidence_file.stat().st_size
    assert record.notes == "test import"
    assert load_manifest(manifest) == [record]


def test_register_does_not_modify_evidence(evidence_file, tmp_path):
    before = evidence_file.read_bytes()
    register_evidence(evidence_file, tmp_path / "m.jsonl")
    assert evidence_file.read_bytes() == before


def test_register_same_content_twice_is_deduplicated(evidence_file, tmp_path):
    manifest = tmp_path / "m.jsonl"
    copy = tmp_path / "copy_of_auth.log"
    copy.write_bytes(evidence_file.read_bytes())

    first = register_evidence(evidence_file, manifest)
    second = register_evidence(copy, manifest)

    assert first == second
    assert len(load_manifest(manifest)) == 1


def test_register_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        register_evidence(tmp_path / "nope.log", tmp_path / "m.jsonl")


def test_verify_detects_tampering(evidence_file, tmp_path):
    record = register_evidence(evidence_file, tmp_path / "m.jsonl")
    assert verify_evidence(record)

    evidence_file.write_bytes(evidence_file.read_bytes() + b"injected line\n")
    assert not verify_evidence(record)


def test_verify_missing_file_is_false(evidence_file, tmp_path):
    record = register_evidence(evidence_file, tmp_path / "m.jsonl")
    evidence_file.unlink()
    assert not verify_evidence(record)


def test_record_round_trips_through_json(evidence_file, tmp_path):
    record = register_evidence(evidence_file, tmp_path / "m.jsonl")
    assert EvidenceRecord.from_json(record.to_json()) == record


def test_load_missing_manifest_is_empty(tmp_path):
    assert load_manifest(tmp_path / "does_not_exist.jsonl") == []
