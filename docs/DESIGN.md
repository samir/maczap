# maczap — Design

> Status: **accepted** (design interview closed 2026-11-14).
> Decisions are numbered `Qn` to match the design interview. Architecture decisions
> with lasting trade-offs live in [`docs/adr/`](adr/).

`maczap` is an open-source command-line tool that uninstalls a macOS application
**completely and safely**: the `.app` bundle plus every trace it left behind
(preferences, caches, Application Support, containers, launch agents/daemons,
privileged helpers, package receipts, …), with a real undo.

---

## 1. Product scope

| Topic | Decision |
|---|---|
| Audience (Q1) | Technical users comfortable with a terminal. |
| Distribution (Q1, Q32) | Homebrew tap `samir/homebrew-tap` and crates.io, built with `dist`. Ad-hoc signed, not notarized in the MVP. |
| License (Q17) | MIT. |
| Name (Q18) | `maczap` (crate, binary, repository). "zap" mirrors Homebrew's term for "remove every trace". |
| Stack (Q9) | Rust, edition 2024 — see [ADR-0001](adr/0001-rust.md). |
| macOS (Q10) | 13 (Ventura) or later. CI on 14 and 15; manual checks on 26. |
| MVP (Q6) | Uninstall one **installed** app. Orphan scan (traces of already-deleted apps) is v2 and plugs in as a new candidate source. General cache/log cleaning is **out of scope**. |
| UI language (Q25) | English. All user-facing strings go through one message catalog so pt-BR can be added later. |
| Telemetry (Q25) | None. No network access unless the user passes `--online`. |

## 2. Commands

| Command | Effect |
|---|---|
| `maczap scan <app>` | Read-only. Never writes anything. Prints the plan; `--json` for machine output; `--background-items` also reads BTM (6–8 s, see §4.3); `--online` also uses the Homebrew API cask list. |
| `maczap uninstall <app>` | Resolves the app, scans, shows the selection UI, quits the app, unloads services, moves the selection to quarantine, records a manifest. Flags: `--dry-run`, `--yes`, `--json`, `--trash`, `--permanent`, `--include-low`, `--online`. BTM is read on a background thread while the user reviews the plan. |
| `maczap list` | Lists quarantine batches (id, date, app, size, item count, age). |
| `maczap restore <batch>` | Moves every item of a batch back. Skips conflicts unless `--overwrite` (which first quarantines the item that is in the way). |
| `maczap purge [<batch>…]` | Deletes quarantine batches permanently. `--older-than 30d`. Never automatic unless the user opts in via config. |
| `maczap doctor` | Preflight: macOS version, TCC permissions (Full Disk Access, App Management), Spotlight status, `brew` presence, quarantine size. |

`<app>` accepts a name (`slack`), a path (`/Applications/Slack.app`) or a bundle id
(`com.tinyspeck.slackmacgap`) (Q22). Search covers `/Applications`, `~/Applications`
(recursively, to catch `Utilities/` and vendor folders) and Spotlight
(`kMDItemContentType == "com.apple.application-bundle"`). Several matches → the user
picks one; with `--yes` the tool aborts instead of guessing.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Error (nothing or not everything could be done because of a failure). |
| 2 | Partial: some selected items were removed, some failed (details in output and manifest). |
| 3 | Aborted by the user or by a guard (nothing was changed by this run). |

## 3. Detection

### 3.1 Identity of the target

From the bundle the tool collects:

* the main bundle id (`CFBundleIdentifier`), name, version, executable name;
* **nested bundle ids** (Q20): every bundle under `Contents/Library/LoginItems`,
  `Contents/Library/LaunchServices`, `Contents/XPCServices`, `Contents/PlugIns`,
  `Contents/Frameworks/*.app`, `Contents/Helpers`, `Contents/MacOS/*.app`;
* the **Team ID** and **entitlements** (application groups, `keychain-access-groups`)
  from the code signature (Q19, Q28);
* package receipts whose files include the bundle (`pkgutil --file-info`, `pkgutil --pkgs`).

### 3.2 Confidence levels (Q3, Q21)

| Level | Source | Selected by default |
|---|---|---|
| `high` | Exact bundle id / nested bundle id / app group / Team ID-prefixed group / launchd label whose `Program`/`ProgramArguments` points into the bundle / file listed in a receipt that belongs only to this app. | yes |
| `curated` | Path listed in the Homebrew cask `zap` stanza of the app's cask. Installed casks come from the local `brew info --json=v2 --installed --cask` (always, ~1 s); every other cask from the Homebrew API, only with `--online`, cached for 7 days in `~/.local/share/maczap/homebrew-casks.json`. A cask matches when it installs a bundle of the same name **and** names one of the app's ids, or when it is installed here. Paths outside the catalog and `com.apple.*` names are dropped. | yes |
| `low` | Name heuristics (app name, executable name, vendor name) in the user or system library. | **no** — needs explicit opt-in (`--include-low` or the UI) |
| `shared` | Resource also used by another installed app of the same Team ID (e.g. `UBF8T346G9.Office`). | **never**, not even with `--yes` |

Every candidate carries a human-readable **reason** ("matches bundle id
`com.foo.Bar.helper` (nested LoginItem)"), shown in the UI and stored in the manifest.

### 3.3 Locations

User level (`~` is the invoking user, never root's home):

```
~/Library/Application Support/<id|name>
~/Library/Application Scripts/<id>
~/Library/Caches/<id|name>
~/Library/Containers/<id>
~/Library/Daemon Containers/<id>          (report only — owned by system services)
~/Library/Group Containers/<group>
~/Library/HTTPStorages/<id>[.binarycookies]
~/Library/WebKit/<id>
~/Library/Cookies/<id>.binarycookies
~/Library/LaunchAgents/<label>.plist
~/Library/Logs/<id|name>
~/Library/Logs/DiagnosticReports/<executable>-*.ips   (low)
~/Library/Preferences/<id>.plist
~/Library/Preferences/ByHost/<id>.<hardware-uuid>.plist
~/Library/Saved Application State/<id>.savedState
~/Library/{Internet Plug-Ins,PreferencePanes,QuickLook,Spotlight,Services,
           Screen Savers,Input Methods,ColorPickers}/<bundle>
~/Library/Audio/Plug-Ins/{Components,HAL,VST,VST3,MAS}/<bundle>
$(getconf DARWIN_USER_CACHE_DIR)/<id>
$(getconf DARWIN_USER_TEMP_DIR)/<id>
```

System level (needs root — §5.3):

```
/Library/Application Support/<id|name>
/Library/Caches/<id|name>
/Library/LaunchAgents/<label>.plist
/Library/LaunchDaemons/<label>.plist
/Library/PrivilegedHelperTools/<id>
/Library/Logs/<id|name>
/Library/Preferences/<id>.plist
/Library/{Internet Plug-Ins,PreferencePanes,QuickLook,Spotlight,Services,
          Screen Savers,Input Methods,ColorPickers}/<bundle>
/Library/Audio/Plug-Ins/{Components,HAL,VST,VST3,MAS}/<bundle>
files listed in an exclusive package receipt (§3.4)
```

### 3.4 Package receipts (Q12)

`pkgutil --files <pkg-id>` is a high-confidence list, with strict rules:

* only **files** and directories created exclusively by this receipt are candidates;
* a directory is never a candidate if any other receipt lists it or anything under it,
  or if it is one of the allowlist roots (§5.1) or above one;
* after the files are moved, `pkgutil --forget <pkg-id>` runs (irreversible action, §6.3).
* App Store-style receipts are not in `pkgutil --file-info`'s index; they are named after
  the bundle id instead. A receipt whose id equals one of the app's ids counts only if its
  file list contains the bundle (`com.microsoft.Excel` on the author's Mac).

### 3.5 Report-only traces (Q16)

The tool lists these with instructions and never touches them:

* Keychain items;
* System Extensions / kernel extensions (`systemextensionsctl uninstall` needs SIP off);
* browser extensions;
* Background Task Management entries (§4.3);
* `~/Library/Daemon Containers` entries;
* traces in other user accounts (Q23) — a one-line notice only.

### 3.6 Protected / special apps (Q7)

* Refused: anything under `/System`, any `com.apple.*` bundle, any app on the sealed
  system volume, any app managed by MDM (managed app list / `Managed Preferences`).
* Homebrew casks: detected through the installed cask list (above). In a terminal maczap
  offers to hand over to `brew uninstall --zap --cask <token>`; otherwise, after the
  uninstall, it prints `brew uninstall --cask --force <token>` to resync Homebrew.
* Mac App Store apps are treated like any other app (the receipt is inside the bundle).

### 3.7 Missing permissions (Q11)

If a location cannot be read because of TCC, it is reported as **`not checked`**,
never as clean. `uninstall` aborts (exit 3) if the main bundle cannot be moved.
Spike 0001 #5: with Full Disk Access, App Management did not block moving, writing
into or deleting a third-party bundle on macOS 26.2; behaviour without FDA is measured
in the VM E2E suite.

## 4. Execution order

1. Acquire the lock (`~/.local/share/maczap/lock`, advisory `flock`) (Q25).
2. Resolve the app, collect identity (§3.1), run the scan.
3. Selection (UI or flags). Show irreversible actions as a separate group (§6.3).
4. **Quit the app** (Q8): `NSRunningApplication.terminate()` for every running
   instance of the main and nested bundle ids; wait up to 10 s **on PID liveness**
   (`kill(pid, 0)`; the LaunchServices list drops the app before the process exits —
   spike 0001 #4); if still running → abort (exit 3). Never `kill -9` by default.
5. **Unload launchd jobs** before moving their plists: `launchctl bootout gui/<uid>/<label>`
   (user agents) and `launchctl bootout system/<label>` (daemons, privileged step).
   rc 3 ("No such process") means already unloaded.
6. **Remove legacy login items** via System Events (`osascript`). BTM entries are
   report-only (§4.3).
7. **Reset TCC grants** — `tccutil reset All <id>` per bundle id — **before** the bundle
   moves: once LaunchServices forgets the id, `tccutil` fails with -10814 (spike 0001 #9).
8. Move the selection to quarantine (§6), user items first, then the privileged step.
9. Irreversible clean-up: `pkgutil --forget`. No `cfprefsd` step is needed once the app
   has quit (spike 0001 #8); **`defaults delete` is never used** (it recreates an empty plist).
10. Write the final manifest, print the summary, release the lock.

### 4.3 Background Task Management

macOS 13+ keeps login/background items in BTM. There is no public API to delete one
entry for another app; `sfltool resetbtm` resets **every** app and is never used.
Entries backed by a launchd plist or by `SMAppService` disappear once the plist or the
bundle is gone. maczap reports the remaining entries; `sfltool dumpbtm` is readable
without root and exposes Team ID, bundle id and parent id per record (spike 0001 #7).

## 5. Safety

### 5.1 Hard path rules (Q13)

Applied by the **guard**, the only code that can create `Verified<Candidate>`:

1. **Allowlist of roots** — a candidate must be strictly inside one of the roots
   of §3.3 (plus `/Applications`, `~/Applications` for the bundle itself, plus the
   receipt rules of §3.4).
2. **Never a root or an ancestor of a root** (`~/Library/Application Support` itself,
   `~/Library`, `~`, `/`, …).
3. **No symlink following** — `lstat` everywhere; a symlink candidate moves the link
   itself; every path component between the root and the candidate must be a real
   directory (no symlinked parent).
4. **Absolute deny-list** — `/System`, `/usr` (except receipt-owned files under
   `/usr/local`), `/bin`, `/sbin`, `/private/var/db` (except via `pkgutil`), `/etc`,
   any `com.apple.*` name, the home directory itself, the quarantine directories.
5. **Re-validation at action time** (TOCTOU) — device, inode, file type and owner
   recorded at scan time must still match immediately before the move.

### 5.2 Process hygiene (Q28)

* External tools are run by **absolute path** (`/bin/launchctl`, `/usr/sbin/pkgutil`,
  `/usr/bin/tccutil`, `/usr/bin/osascript`, `/usr/bin/mdfind`, `/usr/bin/sudo`,
  `/usr/bin/ditto`), never through `PATH` or a shell, with arguments as `argv` and a
  timeout.
* A single run holds the lock; a second run fails fast.

### 5.3 Privilege escalation (Q4, Q29)

maczap runs as the invoking user. System-level items are handled by
`sudo /path/to/maczap __apply-system`, which receives the **selection on stdin** and:

1. recomputes the system-level candidates from the bundle id **by itself**;
2. accepts only selected items that are in its own recomputed set;
3. re-applies every guard of §5.1;
4. moves items into the system quarantine and writes the result to stdout;

the user process merges the result into the batch manifest. A tampered selection can
therefore never make root delete an arbitrary path.

## 6. Removal, quarantine, restore (Q2, Q14, Q15, Q24, Q31)

### 6.1 Modes

* **Quarantine** (default): items are moved, not deleted.
  * user items → `~/.local/share/maczap/quarantine/<batch-id>/`
  * system items → `/Library/Application Support/maczap/quarantine/<batch-id>/` (root-owned,
    so owner, mode and xattrs survive).
* `--trash`: user items go to the Trash (`NSFileManager.trashItem`); no restore support.
* `--permanent`: delete. Requires an extra confirmation unless `--yes`.

### 6.2 Moving

* Same volume → atomic `rename(2)`.
* Cross-volume → `ditto` copy, verify (file count + total size + type), then delete the
  source. On verification failure the source is kept and the item is marked failed.

### 6.3 Manifest

JSON, `schema_version`, one per batch, **written ahead** of each move and updated after
it, so an interrupted run can still be restored.

* Batch: id, timestamps, maczap version, user, app (name, bundle id, Team ID, version), mode.
* Item: original path, quarantine path, kind, owner, mode, device, inode, size,
  file count, mtime, category, confidence, reason, status (`planned`, `moved`,
  `failed`, `restored`).
* Irreversible actions (separate list): `launchctl bootout` (with the `launchctl print`
  output for reference), `tccutil reset`, `pkgutil --forget` (with `--pkg-info` output),
  legacy login item removal. `restore` explains what it cannot undo.

### 6.4 Purge

Manual only (`maczap purge`). Every run prints the quarantine size and the batches
older than 30 days. Automatic purge exists only as an opt-in config setting.

## 7. User interface (Q5, Q30)

* `scan` is strictly read-only.
* `uninstall` opens a `ratatui` screen: items grouped by category, colour by confidence
  (green high, cyan curated, yellow low, grey kept), size per item, a details pane with
  the match reason. Keys: `↑/↓` or `j/k`, `PgUp/PgDn`, `space` toggle (refused for kept
  items), `a` select all high + curated, `n` none, `Enter` confirm (refused when nothing
  is selected), `q`/`Esc` cancel.
* Without a TTY, or with `--yes` / `--json`, no TUI is shown.
* Log per run in `~/Library/Logs/maczap/` (paths only, no file contents).

## 8. Architecture (Q27)

```
crates/
  maczap-core/   library: identity, discovery, confidence, guard, plan,
                 quarantine, manifest, restore, purge
  maczap/        binary: CLI (clap), TUI (ratatui), privileged entry point
```

* Every OS access goes through the `Platform` trait: `MacPlatform` in production,
  `FakePlatform` (injectable root, fake processes/launchd/receipts) in tests.
* Native APIs via `objc2`: code signature (Team ID, entitlements) and
  `NSRunningApplication`. Everything without a public API goes through §5.2 subprocesses.
* `Control` (actions: quit, launchd, TCC, login items) is a separate trait from
  `Platform` (read-only facts), so `scan` cannot act. `PrivilegedStep` is the root side.

Core modules: `catalog` (locations = discovery rules + guard roots), `identity`,
`discovery` (+ `background_items`), `receipts`, `zap`, `btm`, `guard`, `plan`,
`quarantine`, `manifest`, `uninstall` (executor), `resolve` (+ protection),
`control`, `platform`, `mac` (real adapters), `command` (subprocess runner).
CLI modules: `env`, `commands`, `batches`, `doctor`, `privileged`, `homebrew`, `tui`,
`lock`, `output`.

## 9. Testing (Q26)

1. Unit and integration tests run against a temporary root with generated fake
   `.app` bundles (Info.plist, nested helpers, fake receipts, fake launchd plists).
2. Dedicated tests for every guard rule: symlink escape, root/ancestor, deny-list,
   inode swap between scan and move.
3. CI: GitHub Actions on macOS 14 and 15.
4. End-to-end tests with real apps (install → uninstall → restore) run only in a
   disposable `tart` VM, never on a developer machine.

As built: the binary's E2E tests run the real executable against a sandbox through the
**debug-only** `MACZAP_SYSTEM_ROOT` variable (release builds ignore it — verified on the
release artifact); in that hermetic mode machine-wide state (BTM, Homebrew) is not read.
Contract tests check `MacPlatform`/`MacControl` against the real Mac; the one that
launches Chess is `#[ignore]`d locally and runs in CI. `scripts/privileged-smoke.sh`
exercises the real `sudo` path with a throw-away root-owned app.

## 10. Implementation order

All ten steps are implemented; see [STATUS.md](STATUS.md) for verification and what is
still open.

1. Spike: code signature via `objc2`, `NSRunningApplication`, real App Management/TCC
   behaviour on macOS 26 — results in [`docs/spikes/`](spikes/).
2. Core: guard + quarantine + manifest (TDD).
3. Discovery and confidence levels.
4. `scan --json`.
5. `uninstall` without TUI.
6. `restore`, `list`, `purge`.
7. TUI.
8. Privileged mode.
9. Homebrew `zap` data.
10. `dist`, CI.
