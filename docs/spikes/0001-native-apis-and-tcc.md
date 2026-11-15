# Spike 0001 — native APIs, TCC and system tools on macOS 26

* Date: 2026-11-14
* Machine: macOS 26.2 (25C56), arm64, terminal iTerm2 with Full Disk Access
* Code: [`spikes/native-spike`](../../spikes/native-spike)
* All probes used throw-away copies or dummy bundles/agents/domains, and were cleaned up.

## Results

| # | Question | Result | Consequence for maczap |
|---|---|---|---|
| 1 | Can `objc2-security` read the Team ID and entitlements? | **Yes.** `SecStaticCodeCreateWithPath` + `SecCodeCopySigningInformation(kSecCSSigningInformation)` return `kSecCodeInfoIdentifier`, `kSecCodeInfoTeamIdentifier`, `kSecCodeInfoEntitlementsDict` (incl. `com.apple.security.application-groups`). Apple system apps have **no** Team ID. A missing path returns `OSStatus -67068`. | Native path confirmed; no `codesign` parsing needed. "No Team ID" must not be read as "Apple" — Apple detection uses the `com.apple.` id + location. |
| 2 | Does `NSRunningApplication.terminate()` work from a CLI without a run loop? | **Yes** (Chess quit; both its processes exited). `runningApplicationsWithBundleIdentifier` is a fresh query each call. | Use it. |
| 3 | What if the app ignores the quit request? | A non-Cocoa app (shell-script bundle) **keeps running**; the wait loop detects it. | Abort path (exit 3) is real and testable. |
| 4 | Is the LaunchServices list a reliable "exited" signal? | It drops the app **immediately** after `terminate()`, before the process is gone. | Wait on **PID liveness** (`kill(pid, 0)`), not on the LaunchServices list. |
| 5 | Does App Management block moving/deleting a third-party bundle? | With Full Disk Access: **no**. Rename out of `/Applications`, writes inside the bundle and `rm -rf` all succeeded, also for a copy that had been launched once (Mac App Store-signed). No `kTCCServiceSystemPolicyAppBundles` row exists for iTerm2. | `doctor` checks Full Disk Access first. The behaviour **without** FDA is still unmeasured (FDA cannot be revoked safely on this machine) → measure in the `tart` VM E2E suite. |
| 6 | `launchctl` return codes | `bootstrap` 0; `print gui/<uid>/<label>` 0 when loaded, **113** when not loaded; `bootout` 0, and **3** ("No such process") when already unloaded. The job's process exits on `bootout`. | Treat `bootout` rc 3 as "already unloaded" (success). Use `print` rc 113 to detect "not loaded". |
| 7 | Can BTM entries be read without root? | **Yes.** `sfltool dumpbtm` (non-root) lists records per UID with `Team Identifier`, `Bundle Identifier`, `Parent Identifier`, `URL`, `Type`, `Disposition`. | Report-only BTM listing is feasible; match on Team ID / bundle id / parent id. |
| 8 | Does `cfprefsd` keep serving a moved preference plist? | **No** (app not running): after moving `<domain>.plist`, `defaults read` reports the domain gone at once; moving it back restores it at once. `defaults delete` on the missing domain **recreates an empty plist**. | No cache-drop step is needed after quitting the app; just verify. **Never call `defaults delete`.** Drop the planned "cfprefsd cache drop" irreversible action. |
| 9 | `tccutil reset All <id>` after the bundle is gone? | Works while LaunchServices still knows the id; **fails with OSStatus -10814 / rc 64** a few seconds after the bundle is moved, even though `lsregister -dump` still lists the new path. | Run `tccutil reset` **before** moving the bundle. Treat rc 64 / -10814 as "nothing to reset". |
| 10 | Spotlight | `mdfind 'kMDItemContentType == "com.apple.application-bundle"'` returned 526 bundles in 0.085 s; `kMDItemCFBundleIdentifier == "<id>"` works. | Use `mdfind` for resolution; fall back to directory walk when `mdutil -s /` says indexing is disabled. |
| 11 | `pkgutil` | `--pkgs` and `--file-info <path>` work without root. | Receipt lookup needs no privilege. |

## Environment notes

* In the Claude Code shell `du` is aliased and `grep` is a shell function — irrelevant for
  the Rust binary, which calls tools by absolute path (DESIGN §5.2).
