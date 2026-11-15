# maczap

Uninstall macOS apps **completely and safely** — the `.app` and every trace it left
behind (preferences, caches, Application Support, containers, launch agents and
daemons, privileged helpers, package receipts…) — with a real undo.

```console
$ maczap scan Rectangle              # read-only: what would go, and why
$ maczap uninstall Rectangle         # pick items, quit the app, move them aside
$ maczap list                        # quarantine batches
$ maczap restore 20261114T201545Z-…  # put a batch back
$ maczap purge --older-than 30d      # delete old batches for good
$ maczap doctor                      # permissions and environment check
```

## Why it is safe

* **Nothing is deleted by default.** Items move to a quarantine with a write-ahead
  manifest; `maczap restore` puts them back. `--trash` and `--permanent` exist, but
  only when you ask.
* **Confidence levels.** Matches on the exact bundle id, nested helper ids, declared
  app groups, launchd jobs and exclusive package receipts are `high`. Paths from
  Homebrew's curated `zap` lists are `curated`. Name-only guesses are `low` and are
  **never** selected unless you opt in (`--include-low` or the selection screen).
  Resources another installed app still uses are `shared` and never removed.
* **A guard the compiler enforces.** Only paths strictly inside a fixed allowlist of
  directories can be moved; roots and their ancestors, `/System`, `/usr`, `com.apple.*`
  names and maczap's own state never can. Symlinks are never followed, and each item
  is re-checked (device, inode, type, owner) through `O_NOFOLLOW` directory handles
  right before it moves.
* **Order matters.** The app is asked to quit (never force-killed) and maczap stops if
  it keeps running; launchd jobs are booted out before their plists move; TCC grants
  are reset while macOS still knows the app.
* **Least privilege.** maczap runs as you. Only items owned by the system go through
  `sudo`, and the privileged step recomputes its own plan instead of trusting the
  request.
* **Apple apps and MDM-managed apps are refused.**

## Install

```console
$ brew install samir/tap/maczap
```

or `cargo install maczap`. Requires macOS 13 or later.

`mz` is a short alias: `mz scan Rectangle` is `maczap scan Rectangle`. Homebrew and
the shell installer add it as a symlink. `cargo install` cannot, so add it yourself:
`ln -s maczap ~/.cargo/bin/mz`.

Give your terminal **Full Disk Access** (System Settings › Privacy & Security) so
maczap can see other apps' containers; locations it cannot read are reported as
*not checked*, never as clean. `maczap doctor` tells you what is missing.

## Commands

| Command | |
|---|---|
| `scan <app>` | Read-only report. `--json`, `--include-low`, `--background-items` (login/background items; takes a few seconds), `--online` (Homebrew cask list from the internet). |
| `uninstall <app>` | Selection screen, then quit + move to quarantine. `--dry-run`, `--yes`, `--json`, `--trash`, `--permanent`, `--include-low`, `--online`. |
| `list` | Quarantine batches (user and system). |
| `restore <batch>` | Put a batch back; `--overwrite` first moves aside whatever is in the way. |
| `purge` | `<batch>…`, `--older-than 30d` or `--all`. System batches need `sudo`. |
| `doctor` | macOS version, Full Disk Access, Spotlight, Homebrew, quarantine size. |

`<app>` is a name, a path to the `.app`, or a bundle id. If several apps match,
maczap asks — and with `--yes` it refuses rather than guess.

Exit codes: `0` success, `1` error, `2` partial (some items failed), `3` aborted
(nothing changed).

## What it does not do

* General cache cleaning, and leftovers of apps already deleted (planned).
* Keychain items, system extensions, browser extensions and Background Task
  Management entries are **reported**, not removed.

## Development

```console
$ make            # list every command
$ make ci         # format check, clippy -D warnings, all tests (what CI runs)
$ make test-contract   # contract tests on this Mac, incl. one that launches Chess
$ make smoke      # real sudo round trip (asks for your password)
$ make dist-build # release archives for Apple Silicon and Intel
```

Design: [docs/DESIGN.md](docs/DESIGN.md) · decisions: [docs/adr](docs/adr) ·
measurements on macOS 26: [docs/spikes](docs/spikes).

## License

MIT
