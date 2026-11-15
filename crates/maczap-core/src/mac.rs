//! `MacPlatform`: the real `Platform` on macOS. Code signatures come from the
//! Security framework (spike 0001 #1); Spotlight and package receipts come from
//! `mdfind` and `pkgutil`.

use std::cell::OnceCell;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;

use objc2_core_foundation::{CFArray, CFDictionary, CFRetained, CFString, CFType, CFURL};
use objc2_security::{
    SecCSFlags, SecCode, SecStaticCode, kSecCSSigningInformation, kSecCodeInfoEntitlementsDict,
    kSecCodeInfoIdentifier, kSecCodeInfoTeamIdentifier,
};

use crate::command::{self, DEFAULT_TIMEOUT};
use crate::platform::{CodeSignature, Platform};

const MDFIND: &str = "/usr/bin/mdfind";
const PKGUTIL: &str = "/usr/sbin/pkgutil";
const SFLTOOL: &str = "/usr/bin/sfltool";

#[derive(Debug, Default)]
pub struct MacPlatform {
    installed: OnceCell<Vec<PathBuf>>,
    /// Extra directories walked for apps when Spotlight is off or misses some.
    app_dirs: Vec<PathBuf>,
}

impl MacPlatform {
    pub fn new(app_dirs: Vec<PathBuf>) -> Self {
        MacPlatform {
            installed: OnceCell::new(),
            app_dirs,
        }
    }
}

impl Platform for MacPlatform {
    fn code_signature(&self, bundle: &Path) -> Option<CodeSignature> {
        signing_information(bundle).map(|info| {
            let string = |key: &CFString| {
                info.get(key)
                    .and_then(|v| v.downcast::<CFString>().ok())
                    .map(|s| s.to_string())
            };
            let app_groups = info
                .get(unsafe { kSecCodeInfoEntitlementsDict })
                .and_then(|v| v.downcast::<CFDictionary>().ok())
                .and_then(|ent| {
                    // SAFETY: entitlement dictionaries are keyed by strings.
                    let ent: &CFDictionary<CFString, CFType> = unsafe { ent.cast_unchecked() };
                    ent.get(&CFString::from_static_str(
                        "com.apple.security.application-groups",
                    ))
                })
                .and_then(|v| v.downcast::<CFArray>().ok())
                .map(|groups| {
                    // SAFETY: the array's elements are type-checked below.
                    let groups: &CFArray<CFType> = unsafe { groups.cast_unchecked() };
                    groups
                        .iter()
                        .filter_map(|g| g.downcast::<CFString>().ok().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            CodeSignature {
                identifier: string(unsafe { kSecCodeInfoIdentifier }),
                team_id: string(unsafe { kSecCodeInfoTeamIdentifier }),
                app_groups,
            }
        })
    }

    fn installed_apps(&self) -> Vec<PathBuf> {
        self.installed
            .get_or_init(|| {
                let mut apps: Vec<PathBuf> = command::run(
                    Path::new(MDFIND),
                    &["kMDItemContentType == \"com.apple.application-bundle\""],
                    DEFAULT_TIMEOUT,
                )
                .map(|out| {
                    out.stdout
                        .lines()
                        .filter(|l| !l.is_empty())
                        .map(PathBuf::from)
                        .collect()
                })
                .unwrap_or_default();
                for dir in &self.app_dirs {
                    walk_apps(dir, 0, &mut apps);
                }
                apps.sort();
                apps.dedup();
                apps
            })
            .clone()
    }

    fn btm_records(&self) -> Vec<crate::btm::BtmRecord> {
        Self::dump_btm()
    }

    fn all_receipts(&self) -> Vec<String> {
        command::run(Path::new(PKGUTIL), &["--pkgs"], DEFAULT_TIMEOUT)
            .map(|out| {
                out.stdout
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn receipts_containing(&self, path: &Path) -> Vec<String> {
        let Ok(out) = command::run(
            Path::new(PKGUTIL),
            &[std::ffi::OsStr::new("--file-info"), path.as_os_str()],
            DEFAULT_TIMEOUT,
        ) else {
            return Vec::new();
        };
        out.stdout
            .lines()
            .filter_map(|l| l.strip_prefix("pkgid: "))
            .map(|s| s.trim().to_string())
            .collect()
    }

    fn receipt_files(&self, pkg_id: &str) -> Option<Vec<PathBuf>> {
        let info =
            command::run(Path::new(PKGUTIL), &["--pkg-info", pkg_id], DEFAULT_TIMEOUT).ok()?;
        if !info.success() {
            return None;
        }
        let field = |name: &str| {
            info.stdout
                .lines()
                .find_map(|l| l.strip_prefix(name).map(|v| v.trim().to_string()))
        };
        let volume = field("volume:").unwrap_or_else(|| "/".into());
        let location = field("location:").unwrap_or_default();
        let base = Path::new(&volume).join(location.trim_start_matches('/'));
        let files = command::run(Path::new(PKGUTIL), &["--files", pkg_id], DEFAULT_TIMEOUT).ok()?;
        if !files.success() {
            return None;
        }
        Some(
            files
                .stdout
                .lines()
                .filter(|l| !l.is_empty() && !l.contains(".."))
                .map(|l| base.join(l))
                .collect(),
        )
    }
}

impl MacPlatform {
    fn dump_btm() -> Vec<crate::btm::BtmRecord> {
        command::run(Path::new(SFLTOOL), &["dumpbtm"], DEFAULT_TIMEOUT)
            .map(|out| crate::btm::parse(&out.stdout))
            .unwrap_or_default()
    }
}

fn walk_apps(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 3 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "app") {
            out.push(path);
        } else {
            walk_apps(&path, depth + 1, out);
        }
    }
}

fn signing_information(bundle: &Path) -> Option<CFRetained<CFDictionary<CFString, CFType>>> {
    let url = CFURL::from_directory_path(bundle)?;
    let mut code: *const SecStaticCode = std::ptr::null();
    // SAFETY: `code` is a valid out-pointer; ownership of the result is taken below.
    let status = unsafe {
        SecStaticCode::create_with_path(&url, SecCSFlags::DefaultFlags, NonNull::from(&mut code))
    };
    let code = NonNull::new(code as *mut SecStaticCode).filter(|_| status == 0)?;
    // SAFETY: a +1 reference returned by a Create function.
    let code = unsafe { CFRetained::from_raw(code) };
    let mut info: *const CFDictionary = std::ptr::null();
    // SAFETY: `info` is a valid out-pointer; ownership of the result is taken below.
    let status = unsafe {
        SecCode::copy_signing_information(
            &code,
            SecCSFlags(kSecCSSigningInformation),
            NonNull::from(&mut info),
        )
    };
    let info = NonNull::new(info as *mut CFDictionary).filter(|_| status == 0)?;
    // SAFETY: a +1 reference returned by a Copy function; its keys are CFStrings.
    let info = unsafe { CFRetained::from_raw(info) };
    Some(unsafe { CFRetained::cast_unchecked(info) })
}

/// The real `Control`.
#[derive(Debug, Default)]
pub struct MacControl;

const LAUNCHCTL: &str = "/bin/launchctl";
const TCCUTIL: &str = "/usr/bin/tccutil";
const OSASCRIPT: &str = "/usr/bin/osascript";

impl crate::control::Control for MacControl {
    fn running_pids(&self, bundle_id: &str) -> Vec<i32> {
        running_apps(bundle_id)
            .iter()
            .map(|a| a.processIdentifier())
            .collect()
    }

    fn request_quit(&self, bundle_id: &str) {
        for app in running_apps(bundle_id) {
            app.terminate();
        }
    }

    fn is_alive(&self, pid: i32) -> bool {
        let Some(pid) = rustix::process::Pid::from_raw(pid) else {
            return false;
        };
        match rustix::process::test_kill_process(pid) {
            Ok(()) => true,
            Err(e) => e != rustix::io::Errno::SRCH,
        }
    }

    fn wait(&self, duration: std::time::Duration) {
        std::thread::sleep(duration);
    }

    fn bootout_user_agent(
        &self,
        label: &str,
        _plist: &Path,
    ) -> Result<crate::control::Bootout, String> {
        let target = format!("gui/{}/{label}", rustix::process::getuid().as_raw());
        let out = command::run(
            Path::new(LAUNCHCTL),
            &["bootout", target.as_str()],
            DEFAULT_TIMEOUT,
        )
        .map_err(|e| e.to_string())?;
        match out.code() {
            Some(0) => Ok(crate::control::Bootout::Unloaded),
            // 3 = "No such process", 113 = "Could not find service" (spike 0001 #6)
            Some(3) | Some(113) => Ok(crate::control::Bootout::NotLoaded),
            _ => Err(format!("launchctl bootout {target}: {}", out.stderr.trim())),
        }
    }

    fn tcc_reset(&self, bundle_id: &str) -> Result<crate::control::TccReset, String> {
        let out = command::run(
            Path::new(TCCUTIL),
            &["reset", "All", bundle_id],
            DEFAULT_TIMEOUT,
        )
        .map_err(|e| e.to_string())?;
        if out.success() {
            return Ok(crate::control::TccReset::Reset);
        }
        // Unknown to LaunchServices: nothing can be reset (spike 0001 #9).
        if out.stderr.contains("-10814") || out.stderr.contains("No such bundle identifier") {
            return Ok(crate::control::TccReset::NothingToReset);
        }
        Err(format!(
            "tccutil reset All {bundle_id}: {}",
            out.stderr.trim()
        ))
    }

    fn remove_legacy_login_item(&self, name: &str) -> Result<(), String> {
        // The name travels as an argument, never inside the script source.
        let script = [
            "-e",
            "on run argv",
            "-e",
            "tell application \"System Events\" to delete login item (item 1 of argv)",
            "-e",
            "end run",
            name,
        ];
        let out = command::run(Path::new(OSASCRIPT), &script, DEFAULT_TIMEOUT)
            .map_err(|e| e.to_string())?;
        if out.success() {
            Ok(())
        } else {
            Err(format!("System Events: {}", out.stderr.trim()))
        }
    }
}

fn running_apps(bundle_id: &str) -> Vec<objc2::rc::Retained<objc2_app_kit::NSRunningApplication>> {
    objc2_app_kit::NSRunningApplication::runningApplicationsWithBundleIdentifier(
        &objc2_foundation::NSString::from_str(bundle_id),
    )
    .iter()
    .collect()
}
