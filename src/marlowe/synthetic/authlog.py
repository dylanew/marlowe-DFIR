"""Synthetic Linux SSH ``auth.log`` generator with ground-truth labels.

Why synthetic data first?
    To *measure* a detector we need to know which events are really
    attacks. Real logs almost never come with that ground truth. A
    generator lets us inject attacks we fully understand, so precision and
    recall mean something. The trade-off is realism: the detector can only
    be as good as our model of "normal", and that limitation is documented
    in ``docs/methodology.md``.

What it simulates
    * Office users logging in by password on weekdays during working hours
      from internal (RFC 1918) addresses, with occasional typos.
    * Remote workers logging in from a fixed public address, and now and
      then from a new one (e.g. a hotel or a new ISP lease). These are
      benign events that *look* suspicious, so they produce realistic false
      positives.
    * A backup service account logging in by public key every night at
      02:00. That is benign off-hours activity.
    * Routine cron sessions, which are noise the parser must cope with.
    * Hard negatives, i.e. benign events that look like attacks: users who
      forget a changed password and fail several times before getting in,
      remote workers logging in late at night, and a monitoring script with
      a stale password that fails every few minutes for hours. A detector
      that flags these is producing false positives, which is exactly what
      we want the evaluation to reveal.

Injected attacks (all from IETF documentation ranges, e.g. 203.0.113.0/24)
    * ``brute_force``: fast password guessing against a few privileged names.
    * ``brute_force_success``: as above, but the attacker eventually gets in.
    * ``password_spray``: one or two attempts each against many usernames,
      slowly, to stay under per-account lockout thresholds.
    * ``off_hours_compromise``: a stolen credential used once, at night, from
      an address the user has never used.

The log lines follow the classic OpenSSH/syslog format. Labels are written
to a *separate* CSV keyed by line number, so the parser and detectors never
see them; only the evaluation step does.
"""

from __future__ import annotations

import csv
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

HOST = "srv01"

OFFICE_USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan"]
REMOTE_USERS = {"judy": "198.51.100.23", "mallory": "198.51.100.77", "oscar": "198.51.100.140"}
SERVICE_USER = "backup"
SERVICE_IP = "10.0.5.10"
MONITOR_IP = "10.0.5.20"
PRIVILEGED_TARGETS = ["root", "admin", "administrator", "ubuntu", "test", "oracle"]
SPRAY_EXTRA_NAMES = ["support", "guest", "user", "deploy", "git", "postgres", "jenkins", "ftp"]

BENIGN = "benign"


@dataclass(order=True)
class LogEvent:
    """One log line before formatting. Sorted by timestamp when written."""

    timestamp: datetime
    message: str = field(compare=False)
    process: str = field(default="sshd", compare=False)
    attack_type: str = field(default=BENIGN, compare=False)
    attack_id: str = field(default="", compare=False)


@dataclass
class GeneratedLog:
    events: list[LogEvent]

    def lines(self) -> list[str]:
        return [
            _format_line(e, pid) for e, pid in zip(self.events, _pids(self.events), strict=True)
        ]

    def write(self, log_path: str | Path, labels_path: str | Path) -> None:
        log_path, labels_path = Path(log_path), Path(labels_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        labels_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("\n".join(self.lines()) + "\n", encoding="utf-8")
        with labels_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["line_no", "is_attack", "attack_type", "attack_id"])
            for line_no, event in enumerate(self.events, start=1):
                writer.writerow(
                    [line_no, int(event.attack_type != BENIGN), event.attack_type, event.attack_id]
                )


def _pids(events: list[LogEvent]) -> list[int]:
    # Deterministic, plausible-looking PIDs; not used by any analysis.
    return [10000 + (i * 7919) % 50000 for i in range(len(events))]


def _format_line(event: LogEvent, pid: int) -> str:
    # Classic syslog timestamps have no year and no timezone, e.g. "Nov  3 09:15:02".
    # This is a real-world parsing problem; the parser has to be told both.
    stamp = f"{event.timestamp:%b} {event.timestamp.day:>2} {event.timestamp:%H:%M:%S}"
    return f"{stamp} {HOST} {event.process}[{pid}]: {event.message}"


def _port(rng: random.Random) -> int:
    return rng.randint(32768, 60999)


def _session(rng: random.Random, ts: datetime, user: str, uid: int, duration_min: float):
    yield LogEvent(
        ts + timedelta(seconds=1),
        f"pam_unix(sshd:session): session opened for user {user}(uid={uid}) by (uid=0)",
    )
    yield LogEvent(
        ts + timedelta(minutes=duration_min),
        f"pam_unix(sshd:session): session closed for user {user}",
    )


def _login(
    rng: random.Random,
    ts: datetime,
    user: str,
    uid: int,
    ip: str,
    method: str = "password",
    typo_rate: float = 0.0,
    attack_type: str = BENIGN,
    attack_id: str = "",
) -> list[LogEvent]:
    events: list[LogEvent] = []
    if rng.random() < typo_rate:
        events.append(LogEvent(ts, f"Failed password for {user} from {ip} port {_port(rng)} ssh2"))
        ts += timedelta(seconds=rng.uniform(3, 15))
    events.append(LogEvent(ts, f"Accepted {method} for {user} from {ip} port {_port(rng)} ssh2"))
    events.extend(_session(rng, ts, user, uid, rng.uniform(5, 240)))
    for e in events:
        e.attack_type, e.attack_id = attack_type, attack_id
    return events


def _benign(rng: random.Random, start: datetime, days: int) -> list[LogEvent]:
    events: list[LogEvent] = []
    office_ips = {u: f"10.0.1.{20 + i}" for i, u in enumerate(OFFICE_USERS)}
    uids = {u: 1001 + i for i, u in enumerate(OFFICE_USERS + list(REMOTE_USERS))}

    for day in range(days):
        date = start + timedelta(days=day)
        weekday = date.weekday() < 5

        # Service account: nightly backup by public key. Benign but off-hours.
        ts = date.replace(hour=2) + timedelta(seconds=rng.randint(0, 90))
        events += _login(rng, ts, SERVICE_USER, 998, SERVICE_IP, method="publickey")

        # Cron noise every hour (not SSH, but present in real auth.log files).
        for hour in range(24):
            ts = date.replace(hour=hour, minute=17)
            events.append(
                LogEvent(
                    ts,
                    "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
                    process="CRON",
                )
            )

        for user in OFFICE_USERS:
            if not weekday and rng.random() > 0.1:
                continue
            for _ in range(rng.randint(1, 4)):
                hour = rng.gauss(12.5, 2.5)
                hour = min(max(hour, 7.5), 19.5)
                ts = date + timedelta(hours=hour, seconds=rng.randint(0, 59))
                events += _login(rng, ts, user, uids[user], office_ips[user], typo_rate=0.06)

        for user, home_ip in REMOTE_USERS.items():
            if not weekday or rng.random() < 0.15:
                continue
            # About 1 in 12 remote logins comes from a new public address.
            ip = home_ip
            if rng.random() < 0.08:
                ip = f"198.51.100.{rng.randint(150, 250)}"
            hour = min(max(rng.gauss(13, 4), 6.5), 23.5)
            ts = date + timedelta(hours=hour, seconds=rng.randint(0, 59))
            events += _login(rng, ts, user, uids[user], ip, typo_rate=0.1)

        # Hard negative: roughly twice a week someone forgot a changed password.
        if weekday and rng.random() < 0.4:
            user = rng.choice(OFFICE_USERS)
            ts = date + timedelta(hours=rng.uniform(8.5, 17), seconds=rng.randint(0, 59))
            for _ in range(rng.randint(3, 6)):
                port = _port(rng)
                msg = f"Failed password for {user} from {office_ips[user]} port {port} ssh2"
                events.append(LogEvent(ts, msg))
                ts += timedelta(seconds=rng.uniform(5, 40))
            events += _login(rng, ts, user, uids[user], office_ips[user])

    # Hard negative: a monitoring account with a stale password retries every
    # 5 minutes for most of one day until someone fixes it. Benign, but it
    # looks like a slow brute force against one account.
    broken_day = start + timedelta(days=min(10, days - 1), hours=6)
    for i in range(rng.randint(100, 140)):
        ts = broken_day + timedelta(minutes=5 * i, seconds=rng.randint(0, 20))
        msg = f"Failed password for nagios from {MONITOR_IP} port {_port(rng)} ssh2"
        events.append(LogEvent(ts, msg))

    return events


def _brute_force(
    rng: random.Random, ts: datetime, ip: str, attack_id: str, succeed: bool
) -> list[LogEvent]:
    attack_type = "brute_force_success" if succeed else "brute_force"
    events = []
    attempts = rng.randint(40, 160)
    for _ in range(attempts):
        user = rng.choice(PRIVILEGED_TARGETS)
        if user == "root":
            msg = f"Failed password for root from {ip} port {_port(rng)} ssh2"
            events.append(LogEvent(ts, msg, attack_type=attack_type, attack_id=attack_id))
        else:
            events.append(
                LogEvent(
                    ts,
                    f"Invalid user {user} from {ip} port {_port(rng)}",
                    attack_type=attack_type,
                    attack_id=attack_id,
                )
            )
            events.append(
                LogEvent(
                    ts + timedelta(seconds=1),
                    f"Failed password for invalid user {user} from {ip} port {_port(rng)} ssh2",
                    attack_type=attack_type,
                    attack_id=attack_id,
                )
            )
        ts += timedelta(seconds=rng.uniform(1.5, 8))
    if succeed:
        events += _login(rng, ts, "root", 0, ip, attack_type=attack_type, attack_id=attack_id)
    return events


def _password_spray(rng: random.Random, ts: datetime, ip: str, attack_id: str) -> list[LogEvent]:
    events = []
    candidates = OFFICE_USERS + list(REMOTE_USERS) + SPRAY_EXTRA_NAMES
    targets = rng.sample(candidates, k=rng.randint(12, len(candidates)))
    valid = set(OFFICE_USERS) | set(REMOTE_USERS)
    for user in targets:
        for _ in range(rng.randint(1, 2)):
            if user in valid:
                msg = f"Failed password for {user} from {ip} port {_port(rng)} ssh2"
                events.append(LogEvent(ts, msg, attack_type="password_spray", attack_id=attack_id))
            else:
                for msg in (
                    f"Invalid user {user} from {ip} port {_port(rng)}",
                    f"Failed password for invalid user {user} from {ip} port {_port(rng)} ssh2",
                ):
                    events.append(
                        LogEvent(ts, msg, attack_type="password_spray", attack_id=attack_id)
                    )
            # Slow: 20 s to 2 min between attempts, to evade simple rate limits.
            ts += timedelta(seconds=rng.uniform(20, 120))
    return events


def _off_hours_compromise(
    rng: random.Random, ts: datetime, ip: str, attack_id: str
) -> list[LogEvent]:
    user = rng.choice(OFFICE_USERS)
    uid = 1001 + OFFICE_USERS.index(user)
    return _login(
        rng,
        ts,
        user,
        uid,
        ip,
        typo_rate=0.5,
        attack_type="off_hours_compromise",
        attack_id=attack_id,
    )


# (day offset, hour, kind). Spread across the period so that both the
# training and the test portions of a time-based split contain attacks.
ATTACK_SCHEDULE = [
    (1, 14.2, "brute_force"),
    (3, 10.5, "password_spray"),
    (5, 3.1, "off_hours_compromise"),
    (6, 22.4, "brute_force"),
    (9, 16.8, "brute_force_success"),
    (10, 11.3, "password_spray"),
    (11, 1.7, "off_hours_compromise"),
    (12, 4.4, "off_hours_compromise"),
    (13, 20.9, "brute_force"),
]


def generate_auth_log(
    start: datetime = datetime(2026, 10, 5),
    days: int = 14,
    seed: int = 42,
) -> GeneratedLog:
    """Generate a labelled synthetic auth.log. The same seed always gives the same log."""
    rng = random.Random(seed)
    events = _benign(rng, start, days)

    for n, (day, hour, kind) in enumerate(ATTACK_SCHEDULE):
        if day >= days:
            continue
        attack_id = f"A{n + 1:02d}"
        ip = f"203.0.113.{10 + n * 13}"
        ts = start + timedelta(days=day, hours=hour)
        if kind == "brute_force":
            events += _brute_force(rng, ts, ip, attack_id, succeed=False)
        elif kind == "brute_force_success":
            events += _brute_force(rng, ts, ip, attack_id, succeed=True)
        elif kind == "password_spray":
            events += _password_spray(rng, ts, ip, attack_id)
        elif kind == "off_hours_compromise":
            events += _off_hours_compromise(rng, ts, ip, attack_id)

    events.sort()
    return GeneratedLog(events)
