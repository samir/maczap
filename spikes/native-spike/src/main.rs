//! Spike: validate the native APIs maczap relies on (docs/DESIGN.md §10 step 1).
//!
//!   native-spike sig <bundle-path>          Team ID, identifier, entitlements
//!   native-spike running <bundle-id>        running instances
//!   native-spike quit <bundle-id> <secs>    graceful quit + wait

use std::ptr::NonNull;
use std::time::{Duration, Instant};

use objc2_app_kit::NSRunningApplication;
use objc2_core_foundation::{
    CFArray, CFBoolean, CFDictionary, CFRetained, CFString, CFType, CFURL,
};
use objc2_foundation::NSString;
use objc2_security::{
    SecCSFlags, SecCode, SecStaticCode, kSecCSSigningInformation,
    kSecCodeInfoEntitlementsDict, kSecCodeInfoIdentifier, kSecCodeInfoTeamIdentifier,
};

fn describe(value: &CFType, depth: usize) -> String {
    let pad = "  ".repeat(depth);
    if let Some(s) = value.downcast_ref::<CFString>() {
        return format!("{s:?}");
    }
    if let Some(b) = value.downcast_ref::<CFBoolean>() {
        return b.as_bool().to_string();
    }
    if let Some(a) = value.downcast_ref::<CFArray>() {
        let a: &CFArray<CFType> = unsafe { a.cast_unchecked() };
        let items: Vec<String> = a.iter().map(|v| describe(&v, depth + 1)).collect();
        return format!("[{}]", items.join(", "));
    }
    if let Some(d) = value.downcast_ref::<CFDictionary>() {
        let d: &CFDictionary<CFString, CFType> = unsafe { d.cast_unchecked() };
        let (keys, values) = d.to_vecs();
        let mut out = String::from("{\n");
        for (k, v) in keys.iter().zip(values.iter()) {
            out += &format!("{pad}  {k} = {}\n", describe(v, depth + 1));
        }
        return out + &pad + "}";
    }
    format!("{value:?}")
}

fn signing_info(path: &str) -> Result<CFRetained<CFDictionary<CFString, CFType>>, i32> {
    let url = CFURL::from_directory_path(path).ok_or(-1)?;
    let mut code: *const SecStaticCode = std::ptr::null();
    let status = unsafe {
        SecStaticCode::create_with_path(&url, SecCSFlags::DefaultFlags, NonNull::from(&mut code))
    };
    if status != 0 || code.is_null() {
        return Err(status);
    }
    let code = unsafe { CFRetained::from_raw(NonNull::new_unchecked(code as *mut SecStaticCode)) };
    let mut info: *const CFDictionary = std::ptr::null();
    let status = unsafe {
        SecCode::copy_signing_information(
            &code,
            SecCSFlags(kSecCSSigningInformation),
            NonNull::from(&mut info),
        )
    };
    if status != 0 || info.is_null() {
        return Err(status);
    }
    let info = unsafe { CFRetained::from_raw(NonNull::new_unchecked(info as *mut CFDictionary)) };
    Ok(unsafe { CFRetained::cast_unchecked(info) })
}

fn cmd_sig(path: &str) {
    match signing_info(path) {
        Err(status) => println!("error: OSStatus {status}"),
        Ok(info) => {
            for (label, key) in [
                ("identifier", unsafe { kSecCodeInfoIdentifier }),
                ("team id", unsafe { kSecCodeInfoTeamIdentifier }),
                ("entitlements", unsafe { kSecCodeInfoEntitlementsDict }),
            ] {
                let shown = info
                    .get(key)
                    .map(|v| describe(&v, 0))
                    .unwrap_or_else(|| "<absent>".into());
                println!("{label}: {shown}");
            }
        }
    }
}

fn running(bundle_id: &str) -> Vec<objc2::rc::Retained<NSRunningApplication>> {
    let apps = NSRunningApplication::runningApplicationsWithBundleIdentifier(&NSString::from_str(
        bundle_id,
    ));
    apps.iter().collect()
}

fn cmd_running(bundle_id: &str) {
    let apps = running(bundle_id);
    println!("{} instance(s)", apps.len());
    for app in apps {
        println!("pid {} terminated={}", app.processIdentifier(), app.isTerminated());
    }
}

fn cmd_quit(bundle_id: &str, secs: u64) {
    let apps = running(bundle_id);
    if apps.is_empty() {
        println!("not running");
        return;
    }
    for app in &apps {
        println!("pid {}: terminate() sent = {}", app.processIdentifier(), app.terminate());
    }
    let start = Instant::now();
    let deadline = start + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if running(bundle_id).is_empty() {
            println!("left the LaunchServices list after {:?}", start.elapsed());
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    println!("STILL RUNNING after {secs}s: {} instance(s)", running(bundle_id).len());
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[1..] {
        ["sig", path] => cmd_sig(path),
        ["running", id] => cmd_running(id),
        ["quit", id, secs] => cmd_quit(id, secs.parse().expect("seconds")),
        _ => eprintln!("usage: native-spike sig <path> | running <id> | quit <id> <secs>"),
    }
}
