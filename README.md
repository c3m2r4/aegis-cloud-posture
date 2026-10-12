# Project AEGIS

AEGIS is a local-first, read-only cloud inventory and security assessment tool for a designated Floci environment. The current CLI is an engineering MVP. It does not claim production readiness, complete AWS compatibility, or compliance certification.

## Install and run

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
aegis doctor
aegis preflight
aegis discover
aegis assess --preview
aegis assess --yes
aegis assess --yes --json
```

Use `aegis assess` without `--yes` in a terminal to receive an interactive confirmation. Non-interactive use must pass `--yes`; otherwise the command exits with code `2` without making assessment calls.

```bash
aegis export --format json [--assessment UUID]
aegis compare PREVIOUS_ASSESSMENT_ID CURRENT_ASSESSMENT_ID
aegis report [--assessment UUID] [--format markdown|json]
```

Configuration is read from exported process variables and an optional `.env` file found in the current directory or its parents. Exported variables take precedence; set `AEGIS_ENV_FILE` to choose a specific file. Defaults target `http://127.0.0.1:4566`, region `us-east-1`, `./aegis.db`, and bounded 3-second connect / 8-second read timeouts. AWS credentials use boto3's standard provider chain, including environment variables or profiles; AEGIS never prints credential values. `.env.example` contains only non-secret settings. Endpoint URLs containing user information, query parameters, fragments, or paths are rejected.

`aegis doctor` checks configuration, SQLite, TCP reachability, credential resolution, and STS identity. TCP reachability alone does not mean the endpoint is ready: doctor exits nonzero and says `Overall readiness: NOT READY` if credentials or STS verification fail. Configure credentials through boto3's standard chain, preferably a dedicated least-privilege profile; do not put values in URLs or screenshots. `COMPLETED` assessments exit zero; `PARTIAL` and `FAILED` assessments exit nonzero. An assessment is partial when an operation fails, is unsupported/incomplete, or a rule returns `NOT_SUPPORTED`/`ERROR`. If discovery obtains no resources, AEGIS records operation errors/unsupported states without fabricating scope resources or vulnerability findings.

`doctor` checks settings, SQLite access, endpoint TCP reachability, and STS. `discover` runs AEGIS's explicitly allowlisted Floci read operations and normalizes each returned resource into the assessment snapshot. The currently verified operations, observed result counts, Floci-console comparison, safe bounds, and limitations are documented in [the discovery coverage audit](docs/DISCOVERY.md). Continuation markers are never ignored: when pagination behavior is not verified, the operation is recorded `INCOMPLETE` and the assessment cannot present that scope as fully enumerated. `assess` performs fresh read-only discovery, evaluates supported rules against that run's inventory, persists findings and evidence links, then summarizes outcomes and failed checks by severity. `export` emits sanitized JSON for the latest or a selected assessment.

`compare OLD_UUID NEW_UUID` compares two persisted assessments and emits versioned JSON containing new, resolved, unchanged, changed, not-reassessed, and uncomparable results plus inventory additions, removals, and observed attribute/name changes. Finding identity is `(rule_id, resource_type, resource_id)`. A missing identity is uncomparable. A failed finding absent from the later assessment is marked not reassessed, never resolved. Resolution requires a later `PASS` or `NOT_APPLICABLE` with references to successful persisted operations and response hashes; `NOT_SUPPORTED`, `ERROR`, missing or unsuccessful evidence, and unsupported-to-pass/fail transitions remain changed or unverified. “New” means a failed finding identity not present in the earlier assessment; a known PASS-to-FAIL transition is reported as changed.

`report [--assessment UUID] [--format markdown|json]` renders the latest stored assessment by default, or the selected assessment. The command only reads SQLite and never starts discovery. JSON uses schema version `1.0`; Markdown includes scope, discovery status coverage, finding counts and evidence references, unsupported operations, errors, and limitations. Severity totals count confirmed `FAIL` outcomes only; unsupported or errored evidence is shown separately and is not described as a pass or confirmed failure.

### Running from another working directory

After installing the package (or activating `.venv`), the `aegis` command is available regardless of the current directory. The default database path `./aegis.db` is relative to the current directory, so select an absolute database path when reading the project's stored history elsewhere:

```bash
cd /tmp
AEGIS_DATABASE=/absolute/path/to/Aegis/aegis.db aegis report --format markdown
AEGIS_DATABASE=/absolute/path/to/Aegis/aegis.db aegis compare OLD_UUID NEW_UUID
```

Replace `/absolute/path/to/Aegis` with the project directory. Use `/absolute/path/to/Aegis/.venv/bin/aegis` instead of `aegis` if the virtual environment is not activated. AEGIS loads `.env` from the current directory or a parent directory; use `AEGIS_ENV_FILE=/path/to/.env` to select a file explicitly. Shell variables override file values.

### Repeatable local Floci run

For local Floci, the ignored project `.env` may contain emulator-only dummy credentials. Never use those values with real AWS. Do not set `AWS_PROFILE` in this case, since selecting a profile can take precedence over environment credentials. For real AWS, configure a dedicated least-privilege profile instead.

```bash
cd /path/to/Aegis

.venv/bin/aegis doctor
.venv/bin/aegis preflight
.venv/bin/aegis assess --preview
.venv/bin/aegis assess --yes
```

`assess` prints its persisted assessment ID. Use the actual printed IDs in chronological order; the second comparison ID must have a later start timestamp. Do not type the example labels literally:

```bash
.venv/bin/aegis compare FIRST_PRINTED_ASSESSMENT_ID SECOND_PRINTED_ASSESSMENT_ID
.venv/bin/aegis report --assessment PRINTED_ASSESSMENT_ID --format markdown
.venv/bin/aegis report --assessment PRINTED_ASSESSMENT_ID --format json
```

`report` and `compare` read SQLite only. They make no cloud requests.

## Implemented rules

| Rule | Severity | Evidence and behavior |
|---|---:|---|
| `AEGIS-IAM-001` Avoid wildcard IAM permissions | High | Reads each local policy's default version. Fails observed `Allow` statements using wildcard actions or resource strings containing `*`; passes only when the returned document is structurally complete and contains no such wildcard. A path pattern such as `bucket/*` may be intentionally scoped; this detector does not establish effective access or exploitability. |
| `AEGIS-EC2-001` Restrict public SSH and RDP ingress | High | Reads security-group ingress. Fails TCP 22/3389 (or all-protocol ingress) from `0.0.0.0/0` or `::/0`. Missing range fields are `NOT_SUPPORTED`; malformed ranges are `ERROR`. |
| `AEGIS-LOGS-001` Use at least 30 days of log retention | Medium | Compares an explicitly returned `retentionInDays` to the local 30-day baseline. Current observations omit that field, so those groups are `NOT_SUPPORTED`; absence is not treated as a failure. This local baseline is not a CIS or other framework mapping. |

Every result is one of `PASS`, `FAIL`, `NOT_APPLICABLE`, `NOT_SUPPORTED`, or `ERROR`, with a reason. `NOT_SUPPORTED` and `ERROR` are never converted to passes. Evidence and resource attributes are redacted before they are persisted or exported. Each finding records its assessment UUID, timestamp, rule/resource identifiers, required operation IDs and evidence hashes, remediation guidance, and comparison with the prior result for the same endpoint/resource/rule.

## Tests

Run deterministic tests with `.venv/bin/pytest -q`. Floci integration tests are opt-in and only run against local Floci after explicitly configured: `AWS_PROFILE=floci-local AEGIS_RUN_INTEGRATION=1 .venv/bin/pytest -q tests/integration`. Integration tests call only read operations and use a temporary SQLite database for assessment persistence. Comparison/report tests use persisted-shaped records and do not access cloud APIs.

## Safety and limitations

AEGIS never invokes the existing lab bootstrap script and has no cloud mutation adapters. The current rules are limited to the verified fields above; discovered types without a rule are inventory only and must not be read as secure. S3 bucket names alone do not support public-access or encryption findings. Log retention is currently unsupported where Floci omits `retentionInDays`. The discovery coverage document distinguishes AEGIS's allowlisted API inventory from Floci console categories; their counts are not expected to match. Pagination continuation behavior remains unverified; any returned marker makes that operation `INCOMPLETE` instead of a complete or empty result. No framework compliance claim or mapping is made. Evidence redaction is heuristic. Local SHA-256 hashes detect changes but do not protect evidence from a privileged host user. Comparison is conservative: missing identities/evaluations cannot prove resolution, and inventory matching is limited to normalized resource type and ID. Reports reflect only the persisted point-in-time snapshot. There is no automatic remediation or attack-path analysis.

See [the synthetic example report](docs/EXAMPLE_OUTPUT.md) for sanitized JSON and Markdown output. Its identifiers and findings are illustrative and do not describe a live account.

## Local dashboard and API

Install the project, dashboard, and test dependencies with `python -m pip install -r requirements.txt` from the project directory, then start the local API with `aegis-web` (or `.venv/bin/aegis-web`). It binds to `127.0.0.1:8000`; set `AEGIS_WEB_PORT` to choose another local port. It reads the same `AEGIS_DATABASE` setting as the CLI. GET routes and page loads never collect cloud data. Explicit same-origin POST actions run preflight discovery or a confirmed assessment.

The initial API exposes `/api/health`, `/api/overview`, `/api/assessments`, assessment detail, findings, resources, operations, JSON/Markdown reports, and persisted assessment comparisons. Assessment identifiers must be UUIDs. List APIs accept bounded `limit` (1–100) and `offset` (0–100000) parameters. Health and overview represent a missing database as an empty first-run state. Existing databases are opened with SQLite read-only mode; requests do not create, initialize, or migrate the database. Raw operation response bodies are never exposed by the API. Reports and comparisons reuse the stored reporting functions and evidence references.

The dashboard is served locally at `http://127.0.0.1:8000/` and includes overview, assessment history, a guided assessment wizard, assessment details, persisted comparisons, setup instructions, and JSON/Markdown report downloads. It fetches saved data from the API; opening or refreshing pages never starts discovery or an assessment. Filtering and pagination use the current API bounds. Comparison selection is limited to the latest 100 saved assessments. Resource attributes, findings, and operation status are shown without raw operation response bodies. Cloud-derived strings are inserted as text, not HTML.

The dashboard has no authentication. Keep it on loopback: loopback binding and Host/Origin checks do not protect against every local threat. Preflight deliberately performs read-only connectivity and discovery calls but does not persist those responses. It may create the configured database parent, briefly creates/removes a write-probe file, and leaves the empty scan-lock sidecar. A confirmed assessment makes a fresh collection and persists sanitized evidence. The server uses an OS lock file adjacent to the configured database to serialize dashboard and CLI runs; the lock is released if its process exits. A browser disconnect does not cancel server-side work, and no retry happens automatically. Run dashboard tests with `.venv/bin/pytest -q tests/unit/test_web_api.py tests/unit/test_web_ui.py`; run the full regression suite with `.venv/bin/pytest -q`.

## Guided assessment workflow

First-time setup: install the optional extras, select endpoint and region, configure a standard boto3 credential provider (an AWS profile is recommended for real environments), and run `aegis doctor`. AEGIS loads `.env` from the current directory or a parent directory without overriding already-exported variables. The default endpoint is local Floci at `http://127.0.0.1:4566`, region `us-east-1`, database `./aegis.db`. Endpoint URLs must be HTTP(S) service base URLs without user information, query, fragment, or path. Use a dedicated least-privilege read-only identity. Never use local emulator credentials with a real provider.

The dashboard **New assessment** flow first loads a local-only preview. The explicit **Run preflight checks** action tests endpoint reachability, credential availability without displaying values, STS identity, database/schema state, and the verified read-operation allowlist. It does not save discovery evidence. Preflight reports `READY`, `READY WITH LIMITATIONS`, or `BLOCKED`; unsupported operations and missing database initialization produce limitations, while unavailable credentials, unverifiable identity, or an incompatible database block assessment launch. Preflight expires after five minutes and is consumed after one launch.

Review the endpoint, region, account identity when returned, resource types, read operations, rule set, pagination status, known unsupported capabilities, evidence outputs, and network/possible-charge notice. **Confirm and start scan** is a separate action. It calls the existing service once; GET status polling does not call cloud APIs. The run state is queued, running, or a persisted terminal status (`COMPLETED`, `PARTIAL`, `FAILED`). No progress percentage is invented. The run UUID is also the persisted assessment ID, allowing terminal state recovery after a web process restart. A persisted `RUNNING` row after restart is shown as `UNKNOWN`; inspect its saved evidence/history before retrying. If the browser disconnects, check assessment history before retrying. A database-scoped lock prevents overlapping discovery or assessment runs across CLI/dashboard processes.

CLI daily flow for local Floci (use actual IDs printed by AEGIS). The ignored `.env` supplies local-only dummy credentials; do not set `AWS_PROFILE` in this flow:

```bash
python -m pip install -r requirements.txt
export AEGIS_ENDPOINT_URL='http://127.0.0.1:4566'
export AEGIS_REGION='us-east-1'
aegis config
aegis doctor
aegis preflight
aegis discover
aegis assess --preview
aegis assess --yes
aegis history
aegis show ASSESSMENT_ID
aegis findings ASSESSMENT_ID --outcome FAIL
aegis resources ASSESSMENT_ID
aegis operations ASSESSMENT_ID
aegis compare PREVIOUS_ID CURRENT_ID
aegis report --assessment ASSESSMENT_ID --format markdown
aegis report --assessment ASSESSMENT_ID --format json
```

`aegis history`, `show`, `findings`, `resources`, `operations`, `export`, `compare`, and `report` read persisted data only. `report` and `compare` do not start discovery; query connections do not create or migrate SQLite. Assessment exit codes are `0` for completed, `1` for failed/partial/runtime issues, and `2` for usage/configuration or missing non-interactive confirmation. `aegis --help` lists commands; `aegis version` prints the installed version. The in-app command guide is at `/guide`.
