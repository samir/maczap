# Status

Last updated: 2026-11-15.

## Done and verified

| Area | Verification |
|---|---|
| Design, ADR, spike | `docs/DESIGN.md`, `docs/adr/0001-rust.md`, `docs/spikes/0001-native-apis-and-tcc.md` (11 probes on macOS 26.2). |
| Guard (Q13) | 15 tests (`tests/guard.rs`), incl. `..` traversal, symlinked parent/root, deny-list, protected paths, case-insensitive bypasses. |
| Quarantine, manifest, restore, list, purge (Q14, Q24, Q31) | 18 tests (`tests/quarantine.rs`) + 1 cross-volume test on a mounted APFS image (`tests/cross_volume.rs`). Mutation-checked: fingerprint check, `O_NOFOLLOW`, cross-volume verification. |
| Identity, discovery, receipts, BTM, Homebrew zap (Q3, Q12, Q19–Q21) | `tests/identity.rs` (6), `tests/discovery.rs` (17), `tests/receipts.rs` (4), `tests/zap.rs` (5), unit tests. Mutation-checked: sub-id ownership, shared groups, duplicate copies. Read-only scans of Rectangle, Microsoft Excel, 1Password and iTerm2 on the author's Mac reviewed by hand. |
| Real adapters | `tests/mac_platform.rs`: signatures, installed apps, receipts, `launchctl`, `tccutil`, process liveness; graceful quit of Chess (`--ignored`). |
| Executor (Q8, §4 order) | 8 tests (`tests/uninstall.rs`) with recording fakes; mutation-checked: bundle preflight, TCC-before-move. |
| Plan, resolve, protection (Q7, Q22) | `tests/plan.rs` (4), `tests/resolve.rs` (6). |
| iPhone/iPad apps (wrapped bundles, UUID containers) | `tests/identity.rs` (4), `tests/resolve.rs` (1), `tests/discovery.rs` (6), 1 E2E round trip (uninstall → restore). Mutation-checked: symlinked inner bundle, wrapper mapping, iOS-only metadata reads, symlinked metadata, UUID-only names, shared ids, `WrappedBundle` choice. Read-only scans of iMoney, PocketPal and Mibo Smart (6 extension containers) on the author's Mac; scans of Rectangle, iTerm2, 1Password, Excel, Docker unchanged. |
| CLI | 7 E2E tests of the real binary on a sandbox (`crates/maczap/tests/e2e.rs`), incl. one through an `mz` symlink; 3 unit tests of the root-side selection; 6 TUI tests (state machine + `TestBackend` render); TUI driven once through a real pseudo-terminal. |
| Release | `dist build` for `aarch64-apple-darwin` and `x86_64-apple-darwin` (both run; x86_64 under Rosetta; ad-hoc signed; test hook absent from release builds). The Homebrew formula and the shell installer add `mz` as a symlink to `maczap` (`bin-aliases`). CI workflow passes locally (`fmt --check`, `clippy -D warnings`, tests). |

Totals: 124 tests pass, 1 ignored locally (launches Chess; runs in CI).

## Open

1. **Real `sudo` round trip not yet run.** `scripts/privileged-smoke.sh` needs an
   administrator password. Run it once: `scripts/privileged-smoke.sh`.
2. **Behaviour without Full Disk Access** (App Management, containers) is unmeasured —
   the author's terminal has FDA. Planned for the `tart` VM suite (not built yet).
3. **Legacy login item type string** in `sfltool dumpbtm` was not observed on the
   author's Mac; maczap treats a record whose type contains `login item` and whose
   flags contain `legacy` as one. Confirm on a Mac that has such an item.
4. **Not published.** The directory is not a git repository yet; nothing has been pushed,
   tagged or released. `dist` expects the GitHub repo `samir/maczap` and the tap
   `samir/homebrew-tap` (the release workflow needs a `HOMEBREW_TAP_TOKEN` secret).
5. **crates.io**: `maczap-core` must be published before `maczap`.
6. v2 scope (DESIGN §1): orphan scan, pt-BR messages, optional auto-purge config.
