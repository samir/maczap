#!/bin/bash
# Smoke test of the privileged step with a real `sudo` (asks for your password).
#
# Creates a throw-away, root-owned app and system traces under dev.maczap.smoke.*,
# then checks: uninstall (user + system batches), restore (ownership kept),
# permanent uninstall. Everything it creates is removed on exit, even on failure.
#
# Usage: scripts/privileged-smoke.sh [path/to/maczap]
set -euo pipefail

MACZAP="${1:-$(cd "$(dirname "$0")/.." && pwd)/target/debug/maczap}"
ID="dev.maczap.smoke.PrivTest"
APP="/Applications/MaczapSmokeTest.app"
SUPPORT="/Library/Application Support/$ID"
DAEMON="/Library/LaunchDaemons/$ID.plist"
PREFS="$HOME/Library/Preferences/$ID.plist"

cleanup() {
  sudo /bin/launchctl bootout "system/$ID" 2>/dev/null || true
  sudo /bin/rm -rf "$APP" "$SUPPORT" "$DAEMON"
  /bin/rm -f "$PREFS"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok   $*"; }

[ -x "$MACZAP" ] || fail "build first: cargo build (missing $MACZAP)"
sudo -v

setup() {
  sudo /bin/mkdir -p "$APP/Contents/MacOS" "$SUPPORT"
  sudo /usr/bin/tee "$APP/Contents/Info.plist" >/dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>$ID</string>
<key>CFBundleName</key><string>MaczapSmokeTest</string>
<key>CFBundleExecutable</key><string>MaczapSmokeTest</string>
</dict></plist>
EOF
  printf '#!/bin/sh\nexit 0\n' | sudo /usr/bin/tee "$APP/Contents/MacOS/MaczapSmokeTest" >/dev/null
  sudo /bin/chmod 755 "$APP/Contents/MacOS/MaczapSmokeTest"
  echo data | sudo /usr/bin/tee "$SUPPORT/state" >/dev/null
  sudo /usr/bin/tee "$DAEMON" >/dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$ID</string>
<key>ProgramArguments</key><array><string>/bin/sleep</string><string>600</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>
EOF
  sudo /usr/sbin/chown -R root:wheel "$APP" "$SUPPORT" "$DAEMON"
  sudo /bin/launchctl bootstrap system "$DAEMON"
  /usr/bin/defaults write "$ID" smoke -string yes
}

gone()    { for p in "$APP" "$SUPPORT" "$DAEMON" "$PREFS"; do [ ! -e "$p" ] || fail "$p still exists"; done; }
present() { for p in "$APP" "$SUPPORT" "$DAEMON" "$PREFS"; do [ -e "$p" ] || fail "$p is missing"; done; }

setup
present
sudo /bin/launchctl print "system/$ID" >/dev/null || fail "daemon not loaded"
pass "fixture created and daemon loaded"

OUT=$("$MACZAP" uninstall "$APP" --yes --json)
echo "$OUT"
BATCH=$(echo "$OUT" | /usr/bin/plutil -extract batch raw -o - -)
SYSTEM_BATCH=$(echo "$OUT" | /usr/bin/plutil -extract system_batch raw -o - -)
[ "$(echo "$OUT" | /usr/bin/plutil -extract complete raw -o - -)" = "true" ] || fail "uninstall incomplete"
gone
if sudo /bin/launchctl print "system/$ID" >/dev/null 2>&1; then fail "daemon still loaded"; fi
pass "uninstall moved user and system items (user batch $BATCH, system batch $SYSTEM_BATCH) and booted out the daemon"

"$MACZAP" list | grep -q "$SYSTEM_BATCH" || fail "list does not show the system batch"
pass "list shows the system batch without sudo"

"$MACZAP" restore "$BATCH"
present
[ "$(/usr/bin/stat -f %Su "$APP")" = "root" ] || fail "bundle owner changed"
[ "$(/usr/bin/stat -f %Su "$SUPPORT/state")" = "root" ] || fail "support owner changed"
pass "restore put everything back with root ownership"

"$MACZAP" purge --all --yes >/dev/null
sudo "$MACZAP" purge --all --yes >/dev/null
[ "$("$MACZAP" list --json)" = "[]" ] || fail "purge left batches behind"
pass "purge (user, then sudo for system) emptied both quarantines"

"$MACZAP" uninstall "$APP" --yes --permanent >/dev/null
gone
[ "$("$MACZAP" list --json)" = "[]" ] || fail "permanent uninstall left a batch"
pass "permanent uninstall left nothing behind"
echo "privileged smoke test passed"
