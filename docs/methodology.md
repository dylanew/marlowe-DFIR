# Methodology: SSH auth.log anomaly detection

This document explains *why* each step of the analysis is done the way it is. The executed analysis, with charts, is in [`notebooks/01_auth_log_anomaly_detection.ipynb`](../notebooks/01_auth_log_anomaly_detection.ipynb).

## 1. The question

Given a Linux `auth.log`, can we surface SSH attacks for an investigator to review, with every lead traceable to specific log lines? The attacks covered are brute force, password spraying and the use of stolen credentials.

This is a **triage** problem. The output is a ranked list of leads, not verdicts.

## 2. Data

### Why synthetic first
Measuring a detector requires ground truth, and real logs almost never have reliable labels. `marlowe generate` (`src/marlowe/synthetic/authlog.py`) produces a 14-day log with a fixed seed, so every run is identical. Labels are written to a separate CSV keyed by line number, so the parser and detectors never see them.

### What's in it
| Activity | Label | Why it's there |
|---|---|---|
| Office users, weekday working hours, internal IPs, occasional typos | benign | the baseline of normal |
| Remote workers on fixed public IPs, sometimes late, sometimes from a new IP | benign | hard negatives: external + new IP + late, yet legitimate |
| `backup` service account, public key, nightly 02:00 | benign | benign off-hours activity |
| Users who forgot a changed password (3–6 failures, then success) | benign | hard negative for "success after failures" |
| Monitoring account with a stale password, failing every 5 min for ~10 h | benign | hard negative that looks like a slow brute force |
| Brute force (40–160 attempts, 1.5–8 s apart) | attack | |
| Brute force that ends in a successful root login | attack | the most serious case |
| Password spray (12–20 usernames, 20–120 s apart) | attack | low-and-slow, harder per window |
| Stolen credential used once at night from a new IP | attack | very quiet: 1–3 lines |

### Limitations of the data
- The generator encodes our *assumptions* about normal and attack behaviour. Detectors designed with the same assumptions will look better than they would on real data. This circularity matters most for the rule baseline.
- One host, 12 users, 14 days. Real environments are far noisier.
- Attack IPs come from IETF documentation ranges (`203.0.113.0/24`), and benign remote workers from `198.51.100.0/24`. Neither range is routable on the real internet.

**Next step:** validate on a public dataset with real behaviour (see the roadmap).

## 3. Parsing and provenance

- The file is registered first: SHA-256, size and UTC time go into an append-only manifest (`marlowe.forensics`).
- **Every line becomes a row.** Lines the parser doesn't recognise are kept as `unparsed`, so coverage can be measured and nothing is silently lost.
- Syslog timestamps have **no year and no timezone**. The caller must supply both, and the parser converts to UTC and keeps the original string. A Dec → Jan rollover is detected. Impossible dates (e.g. Feb 30) become `unparsed` rather than being guessed.

## 4. Unit of analysis and features

Each row of the feature table is **one source IP in one 10-minute tumbling window**. SSH attacks are defined by volume, variety and sequence over short periods, and they are attacker-centric (one source, many accounts).

| Feature | Intuition |
|---|---|
| `n_events`, `n_failed`, `n_success`, `n_invalid_user` | volume |
| `n_distinct_users` | variety: spraying hits many accounts |
| `failure_ratio` | mostly failing vs mostly succeeding |
| `success_after_failure` | sequence: got in after failing |
| `n_success_off_hours` | successes outside 07:00–20:00 UTC |
| `n_new_user_ip_success` | first-ever success for that user from that IP |
| `is_new_ip` | first time this IP has been seen at all |
| `is_internal_ip` | inside the organisation's own ranges (configurable) |
| `hour_sin`, `hour_cos` | time of day on a circle, so 23:00 is close to 01:00 |

**No future leakage:** the history features only look backwards.

**A bug the tests caught:** Python's `ipaddress.is_private` returns `True` for documentation ranges such as `203.0.113.0/24`, which would have marked every attacker as internal. Internal networks are therefore an explicit, configurable list.

## 5. Detectors

### Rule baseline (`marlowe/detection/rules.py`)
Four readable rules. The thresholds come from common SSH-hardening practice and were **fixed before evaluation**:
- `brute_force`: ≥ 10 failures in a window
- `password_spray`: ≥ 5 distinct usernames with ≥ 80% failures
- `success_after_failures`: a success after ≥ 3 failures in the window
- `off_hours_new_source`: an off-hours success from a never-before-seen (user, IP)

A baseline is essential. If simple rules are as good as ML, the ML is not worth its complexity.

### Isolation Forest (`marlowe/detection/isolation_forest.py`)
- It is unsupervised, so it needs no labels (labelled attacks are rare in practice).
- Counts are `log1p`-transformed, then standardised.
- It is trained **only on the training period**, and its flag threshold is the 98th percentile of training scores (`contamination=0.02`, chosen in advance).
- Each flag is explained by the features furthest from their training median, measured in IQR units. This is a simple, honest proxy for "why", not a full attribution method like SHAP.

## 6. Evaluation design

- **Time-based split:** the first 60% of the timeline trains and the last 40% tests. A random split would leak the future, because IPs first seen in the test period would no longer look "new".
- **No accuracy:** with ~6% positives, flagging nothing scores ~94%.
- **Metrics:** precision, recall and F1 at window level; average precision (area under the PR curve), which is threshold-free and suited to rare positives; and **incident-level detection**: was *any* window of each attack flagged? That last one is what matters to an investigator.
- **Sensitivity analysis** across thresholds is shown in the notebook for diagnosis only, never for picking the threshold.

## 7. Results (seed 42, test period)

| Detector | Precision | Recall | F1 | FP | Avg. precision |
|---|---|---|---|---|---|
| Rules | 0.89 | 0.73 | 0.80 | 1 | – |
| Isolation Forest | 1.00 | 0.45 | 0.62 | 0 | 0.96 |
| Either | 0.90 | 0.82 | 0.86 | 1 | – |

**Incidents:** the rules detected 5 of 5 test-period incidents and the Isolation Forest 2 of 5.

### Interpretation
- The rules do well, which is partly circular (see §2).
- The Isolation Forest **ranks** well (AP 0.96), but the conservative threshold only flags the loudest bursts. Its recall jumps to 0.82 at 5% contamination, and at 10% it collapses into 44 false positives, mostly the broken monitoring account. The threshold choice matters more than the model.
- The two detectors are complementary: rules explain *known* patterns, and the model ranks *unusual* ones.

### Error analysis
- **False positive:** a user with 4 failed attempts followed by a success (a forgotten password). This is the classic weakness of the `success_after_failures` rule.
- **Missed windows:** the early, quiet windows of a password spray (2–7 failures, at most 4 users). They fall below every rule threshold and look like normal typos.
- **Window boundary effect:** for the brute force that succeeded, the successful root login fell in a *new* window containing only 2 failures, so `success_after_failures` missed the single most important line. The Isolation Forest flagged that window. Sliding windows, or a "failures from this IP in the last 30 minutes" feature, would fix this.

## 8. What can and cannot be concluded

- **Can:** on this synthetic data, simple, explainable rules plus an unsupervised ranker surface every injected incident, with one benign false positive. Every finding traces to evidence lines.
- **Cannot:** that this would perform similarly on real logs; that a flagged window is malicious; or that the Isolation Forest beats rules in general (the test set has only 11 attack windows across 5 incidents).
