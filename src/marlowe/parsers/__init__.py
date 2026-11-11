"""Source-specific parsers that turn raw evidence into normalised tables."""

from marlowe.parsers.linux_auth import COLUMNS, parse_auth_log, parse_lines

__all__ = ["COLUMNS", "parse_auth_log", "parse_lines"]
