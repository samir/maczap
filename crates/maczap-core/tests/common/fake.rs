#![allow(dead_code)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use maczap_core::platform::{CodeSignature, Platform};
use plist::{Dictionary, Value};

/// Builds a fake application bundle on disk.
pub struct FakeApp {
    pub path: PathBuf,
    info: Dictionary,
    binary_plist: bool,
}

impl FakeApp {
    pub fn new(parent: &Path, name: &str, bundle_id: &str) -> Self {
        let mut info = Dictionary::new();
        info.insert("CFBundleIdentifier".into(), Value::String(bundle_id.into()));
        info.insert("CFBundleName".into(), Value::String(name.into()));
        info.insert("CFBundleExecutable".into(), Value::String(name.into()));
        info.insert("CFBundlePackageType".into(), Value::String("APPL".into()));
        FakeApp {
            path: parent.join(format!("{name}.app")),
            info,
            binary_plist: false,
        }
    }

    pub fn set(mut self, key: &str, value: &str) -> Self {
        self.info.insert(key.into(), Value::String(value.into()));
        self
    }

    pub fn remove(mut self, key: &str) -> Self {
        self.info.remove(key);
        self
    }

    pub fn binary_plist(mut self) -> Self {
        self.binary_plist = true;
        self
    }

    pub fn build(self) -> PathBuf {
        write_bundle(&self.path, &self.info, self.binary_plist);
        let exe = self.path.join("Contents/MacOS").join(
            self.info
                .get("CFBundleExecutable")
                .and_then(Value::as_string)
                .unwrap_or("bin"),
        );
        fs::create_dir_all(exe.parent().unwrap()).unwrap();
        fs::write(exe, "#!/bin/sh\n").unwrap();
        self.path
    }
}

/// Writes `<bundle>/Contents/Info.plist`.
pub fn write_bundle(bundle: &Path, info: &Dictionary, binary: bool) {
    let plist = bundle.join("Contents/Info.plist");
    fs::create_dir_all(plist.parent().unwrap()).unwrap();
    let value = Value::Dictionary(info.clone());
    if binary {
        value.to_file_binary(&plist).unwrap();
    } else {
        value.to_file_xml(&plist).unwrap();
    }
}

/// A nested bundle (helper, extension, XPC service) inside an app.
pub fn nested_bundle(app: &Path, relative: &str, bundle_id: &str) -> PathBuf {
    let path = app.join(relative);
    let mut info = Dictionary::new();
    info.insert("CFBundleIdentifier".into(), Value::String(bundle_id.into()));
    write_bundle(&path, &info, false);
    path
}

pub fn write_plist(path: &Path, entries: &[(&str, Value)]) {
    let mut dict = Dictionary::new();
    for (k, v) in entries {
        dict.insert((*k).into(), v.clone());
    }
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    Value::Dictionary(dict).to_file_xml(path).unwrap();
}

#[derive(Default)]
pub struct FakePlatform {
    pub signatures: HashMap<PathBuf, CodeSignature>,
    pub installed: Vec<PathBuf>,
    pub file_info: HashMap<PathBuf, Vec<String>>,
    pub receipts: HashMap<String, Vec<PathBuf>>,
    pub btm: Vec<maczap_core::btm::BtmRecord>,
}

impl FakePlatform {
    pub fn sign(&mut self, bundle: &Path, team: &str, groups: &[&str]) {
        self.signatures.insert(
            bundle.to_path_buf(),
            CodeSignature {
                identifier: None,
                team_id: Some(team.into()),
                app_groups: groups.iter().map(|g| g.to_string()).collect(),
            },
        );
    }

    /// Registers a receipt: `pkgutil --files` returns `files`, and `--file-info` of
    /// each file returns this package (plus whatever was registered before).
    pub fn receipt(&mut self, pkg: &str, files: &[PathBuf]) {
        self.receipts.insert(pkg.into(), files.to_vec());
        for f in files {
            self.file_info
                .entry(f.clone())
                .or_default()
                .push(pkg.into());
        }
    }
}

impl Platform for FakePlatform {
    fn code_signature(&self, bundle: &Path) -> Option<CodeSignature> {
        self.signatures.get(bundle).cloned()
    }

    fn installed_apps(&self) -> Vec<PathBuf> {
        self.installed.clone()
    }

    fn receipts_containing(&self, path: &Path) -> Vec<String> {
        self.file_info.get(path).cloned().unwrap_or_default()
    }

    fn receipt_files(&self, pkg_id: &str) -> Option<Vec<PathBuf>> {
        self.receipts.get(pkg_id).cloned()
    }

    fn all_receipts(&self) -> Vec<String> {
        let mut all: Vec<String> = self.receipts.keys().cloned().collect();
        all.sort();
        all
    }

    fn btm_records(&self) -> Vec<maczap_core::btm::BtmRecord> {
        self.btm.clone()
    }
}

/// An iPhone/iPad app as macOS installs it on Apple silicon: `<outer>.app` holds
/// `Wrapper/<inner>.app` (flat iOS layout, `Info.plist` at its root) and a
/// `WrappedBundle` symlink to it. Returns (outer, inner).
pub fn wrapped_ios_app(
    parent: &Path,
    outer: &str,
    inner: &str,
    bundle_id: &str,
    display_name: &str,
) -> (PathBuf, PathBuf) {
    let outer_path = parent.join(format!("{outer}.app"));
    let inner_path = outer_path.join(format!("Wrapper/{inner}.app"));
    let mut info = Dictionary::new();
    info.insert("CFBundleIdentifier".into(), Value::String(bundle_id.into()));
    info.insert("CFBundleName".into(), Value::String(inner.into()));
    info.insert(
        "CFBundleDisplayName".into(),
        Value::String(display_name.into()),
    );
    info.insert("CFBundleExecutable".into(), Value::String(inner.into()));
    info.insert("CFBundlePackageType".into(), Value::String("APPL".into()));
    info.insert(
        "CFBundleSupportedPlatforms".into(),
        Value::Array(vec![Value::String("iPhoneOS".into())]),
    );
    fs::create_dir_all(&inner_path).unwrap();
    Value::Dictionary(info)
        .to_file_xml(inner_path.join("Info.plist"))
        .unwrap();
    fs::write(inner_path.join(inner), "bin").unwrap();
    fs::write(outer_path.join("Wrapper/BundleMetadata.plist"), "x").unwrap();
    fs::write(outer_path.join("Wrapper/iTunesMetadata.plist"), "x").unwrap();
    std::os::unix::fs::symlink(
        format!("Wrapper/{inner}.app"),
        outer_path.join("WrappedBundle"),
    )
    .unwrap();
    (outer_path, inner_path)
}

/// A nested bundle in the flat iOS layout (`Info.plist` at its root), e.g. an
/// extension in `PlugIns/` of an iOS app.
pub fn flat_nested_bundle(app: &Path, relative: &str, bundle_id: &str) -> PathBuf {
    let path = app.join(relative);
    write_plist(
        &path.join("Info.plist"),
        &[("CFBundleIdentifier", Value::String(bundle_id.into()))],
    );
    path
}

/// The data container of an iOS app: `~/Library/Containers/<UUID>`, with the owner's
/// bundle id in its containermanagerd metadata.
pub fn ios_container(home: &Path, uuid: &str, bundle_id: &str) -> PathBuf {
    let container = home.join("Library/Containers").join(uuid);
    write_plist(
        &container.join(".com.apple.containermanagerd.metadata.plist"),
        &[("MCMMetadataIdentifier", Value::String(bundle_id.into()))],
    );
    fs::create_dir_all(container.join("Data/Documents")).unwrap();
    fs::write(container.join("Data/Documents/db.sqlite"), "x").unwrap();
    container
}
