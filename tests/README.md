# Tests

Self-contained test suite for the connection monitor scripts.

```bash
./tests/run-tests.sh
```

- **No root, no network, no extra tooling** required (only `bash` and `python3`,
  which the project already depends on).
- System commands (`w`, `ss`, `loginctl`, `curl`, `wget`) are **stubbed**, so the
  results are deterministic and safe to run anywhere, including CI.
- Exits non-zero if any test fails.

## What is covered

| Area | What it verifies |
|------|------------------|
| Syntax | `bash -n` on every script |
| `html_escape` | `&`/`<`/`>` escaping in both scripts, incl. the bash 5.2 `patsub_replacement` pitfall, no double-escaping |
| `get_active_sessions` | command/username HTML-escaping, IPv6 peer parsing, per-IP dedup (`1.2.3.4` vs `1.2.3.40`), alphanumeric `loginctl` session ids, remote-host detection, totals |
| connection alert | message build → `json_escape` produces valid JSON for an `AT&T`-style ISP and a hostile username, while keeping intended `<b>`/`<code>` tags |
| `fetch()` | selects `curl`, falls back to `wget`, returns `127` when neither exists |
| `ask()` | non-interactive safety for `curl \| bash` (uses default instead of hanging / aborting) |
| shellcheck | run automatically if installed, otherwise skipped |

## Adding tests

Add assertions inside `run-tests.sh` using the helpers `assert_eq`,
`assert_contains`, and `assert_not_contains`. Real functions are pulled from the
scripts with `extract <file> <function>` and executed under `/bin/bash` with
stubbed system commands, so tests exercise the actual shipped code.
