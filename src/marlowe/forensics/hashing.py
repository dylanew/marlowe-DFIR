"""Evidence hashing and provenance.

Every file Marlowe analyses is registered first. Registration records a
SHA-256 hash, the file's size, its original path and the time it was
imported, and appends that record to an append-only JSON Lines manifest.

Why this matters:
    * The hash lets us prove later that the file we analysed is the same
      file we were given (integrity).
    * The manifest is an audit trail: it says what was imported, when and
      by which version of the tool (provenance).
    * Nothing in this module ever modifies the evidence file itself; it is
      only ever opened for reading.

Why JSON Lines: one JSON object per line means we only ever *append*,
never rewrite, so an existing entry cannot be silently altered by a bug
in a later import.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from marlowe import __version__

# Read files in 1 MiB chunks so large evidence (e.g. multi-GB logs or
# images) is hashed without loading the whole file into memory.
_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class EvidenceRecord:
    """One entry in the evidence manifest.

    ``frozen=True`` makes records immutable once created, which mirrors the
    rule that recorded provenance should never be edited after the fact.
    """

    evidence_id: str
    original_path: str
    file_name: str
    size_bytes: int
    sha256: str
    registered_at_utc: str
    tool_version: str
    notes: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls, line: str) -> EvidenceRecord:
        return cls(**json.loads(line))


def sha256_file(path: str | Path) -> str:
    """Return the hex SHA-256 digest of a file, reading it in chunks."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(manifest_path: str | Path) -> list[EvidenceRecord]:
    """Read all records from a manifest. A missing manifest means no evidence yet."""
    manifest_path = Path(manifest_path)
    if not manifest_path.exists():
        return []
    with manifest_path.open(encoding="utf-8") as handle:
        return [EvidenceRecord.from_json(line) for line in handle if line.strip()]


def register_evidence(
    path: str | Path,
    manifest_path: str | Path,
    notes: str = "",
) -> EvidenceRecord:
    """Hash a file and append its provenance record to the manifest.

    The evidence ID is the first 12 hex characters of the hash. That keeps
    IDs short enough to cite in reports and explanations, while still being
    derived from the content rather than from a mutable file name.

    If a file with the same hash is already registered, the existing record
    is returned instead of creating a duplicate entry.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Evidence file not found: {path}")

    file_hash = sha256_file(path)

    for existing in load_manifest(manifest_path):
        if existing.sha256 == file_hash:
            return existing

    record = EvidenceRecord(
        evidence_id=file_hash[:12],
        original_path=str(path.resolve()),
        file_name=path.name,
        size_bytes=path.stat().st_size,
        sha256=file_hash,
        registered_at_utc=datetime.now(UTC).isoformat(timespec="seconds"),
        tool_version=__version__,
        notes=notes,
    )

    manifest_path = Path(manifest_path)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("a", encoding="utf-8") as handle:
        handle.write(record.to_json() + "\n")

    return record


def verify_evidence(record: EvidenceRecord, path: str | Path | None = None) -> bool:
    """Re-hash a file and check it still matches its registered hash.

    ``path`` defaults to the path recorded at registration, but can be given
    explicitly when the evidence copy has been moved.
    """
    target = Path(path) if path is not None else Path(record.original_path)
    if not target.is_file():
        return False
    return sha256_file(target) == record.sha256
