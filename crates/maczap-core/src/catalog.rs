//! Where traces live (DESIGN §3.3). The catalog is the single source of truth for
//! both discovery (what to look at, and how) and the guard's allowlist.

use std::path::{Path, PathBuf};

use crate::candidate::Category;
use crate::roots::{Roots, Scope};

/// How entries of a location are matched against the target app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Entries named after a bundle id: `<id>`, `<id>.plist`, `<id>.<sub>`, …
    ById,
    /// `ById`, plus low-confidence matches on the app or executable name.
    ByIdOrName,
    /// App group containers (`<TEAMID>.<group>`, `group.<…>`).
    GroupContainers,
    /// launchd job plists, matched on their contents.
    Launchd,
    /// Privileged helper tools, matched by name or by a matched launchd job.
    Helpers,
    /// Plug-in bundles, matched on their own bundle id.
    Plugins,
    /// Crash reports named after the executable.
    CrashReports,
    /// Matched like `ById` but never removed: reported only.
    ReportOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub path: PathBuf,
    pub scope: Scope,
    pub category: Category,
    pub rule: Rule,
}

#[derive(Debug, Clone)]
pub struct Catalog {
    pub home: PathBuf,
    pub system_root: PathBuf,
    pub locations: Vec<Location>,
    /// Where application bundles may live (allowed for the bundle itself only).
    pub app_dirs: Vec<(PathBuf, Scope)>,
    /// Extra roots for files installed by package receipts.
    pub receipt_roots: Vec<PathBuf>,
}

const PLUGIN_DIRS: &[&str] = &[
    "Internet Plug-Ins",
    "PreferencePanes",
    "QuickLook",
    "Spotlight",
    "Services",
    "Screen Savers",
    "Input Methods",
    "ColorPickers",
    "Audio/Plug-Ins/Components",
    "Audio/Plug-Ins/HAL",
    "Audio/Plug-Ins/VST",
    "Audio/Plug-Ins/VST3",
    "Audio/Plug-Ins/MAS",
];

impl Catalog {
    /// The production catalog. `system_root` is `/` on a real machine; tests point it
    /// (and `home`) into a sandbox. The per-user cache and temp directories come from
    /// `getconf DARWIN_USER_CACHE_DIR` / `DARWIN_USER_TEMP_DIR`.
    pub fn standard(
        home: &Path,
        system_root: &Path,
        user_cache_dir: Option<&Path>,
        user_temp_dir: Option<&Path>,
    ) -> Self {
        use Category::*;
        use Rule::*;
        // Discovery builds candidate paths from these, and the guard compares them with
        // canonical roots: resolve symlinks such as /var → /private/var up front.
        let home = &canonical(home);
        let system_root = &canonical(system_root);
        let user_cache_dir = user_cache_dir.map(canonical);
        let user_temp_dir = user_temp_dir.map(canonical);
        let user = |p: &str| home.join("Library").join(p);
        let system = |p: &str| system_root.join("Library").join(p);
        let mut locations = Vec::new();
        let mut add = |path: PathBuf, scope, category, rule| {
            locations.push(Location {
                path,
                scope,
                category,
                rule,
            })
        };

        add(
            user("Application Support"),
            Scope::User,
            ApplicationSupport,
            ByIdOrName,
        );
        add(
            user("Application Scripts"),
            Scope::User,
            ApplicationScripts,
            ById,
        );
        add(user("Caches"), Scope::User, Caches, ByIdOrName);
        add(user("Containers"), Scope::User, Containers, ById);
        add(
            user("Group Containers"),
            Scope::User,
            Category::GroupContainers,
            Rule::GroupContainers,
        );
        add(user("HTTPStorages"), Scope::User, WebData, ById);
        add(user("WebKit"), Scope::User, WebData, ById);
        add(user("Cookies"), Scope::User, WebData, ById);
        add(user("LaunchAgents"), Scope::User, LaunchAgent, Launchd);
        add(user("Logs"), Scope::User, Logs, ByIdOrName);
        add(
            user("Logs/DiagnosticReports"),
            Scope::User,
            Category::CrashReports,
            Rule::CrashReports,
        );
        add(user("Preferences"), Scope::User, Preferences, ById);
        add(user("Preferences/ByHost"), Scope::User, Preferences, ById);
        add(
            user("Saved Application State"),
            Scope::User,
            SavedState,
            ById,
        );
        add(
            user("Daemon Containers"),
            Scope::User,
            Containers,
            ReportOnly,
        );
        for dir in PLUGIN_DIRS {
            add(user(dir), Scope::User, Plugin, Plugins);
        }
        for dir in [user_cache_dir, user_temp_dir].into_iter().flatten() {
            add(dir, Scope::User, TempData, ById);
        }

        add(
            system("Application Support"),
            Scope::System,
            ApplicationSupport,
            ByIdOrName,
        );
        add(system("Caches"), Scope::System, Caches, ByIdOrName);
        add(system("Logs"), Scope::System, Logs, ByIdOrName);
        add(system("Preferences"), Scope::System, Preferences, ById);
        add(system("LaunchAgents"), Scope::System, LaunchAgent, Launchd);
        add(
            system("LaunchDaemons"),
            Scope::System,
            LaunchDaemon,
            Launchd,
        );
        add(
            system("PrivilegedHelperTools"),
            Scope::System,
            PrivilegedHelper,
            Helpers,
        );
        for dir in PLUGIN_DIRS {
            add(system(dir), Scope::System, Plugin, Plugins);
        }

        let usr_local = |p: &str| system_root.join("usr/local").join(p);
        Catalog {
            home: home.to_path_buf(),
            system_root: system_root.to_path_buf(),
            locations,
            app_dirs: vec![
                (system_root.join("Applications"), Scope::System),
                // A root of its own so the folder itself can never be removed.
                (system_root.join("Applications/Utilities"), Scope::System),
                (home.join("Applications"), Scope::User),
            ],
            receipt_roots: [
                "bin", "sbin", "lib", "libexec", "share", "etc", "include", "opt",
            ]
            .iter()
            .map(|p| usr_local(p))
            .collect(),
        }
    }

    /// The guard's roots: every location, the app directories and the receipt roots
    /// are allowed; system directories are denied; `protected` (maczap's own state,
    /// e.g. the quarantine directories) can never be touched.
    pub fn roots(&self, protected: &[PathBuf]) -> std::io::Result<Roots> {
        let mut roots = Roots::new(&self.home)?;
        for location in &self.locations {
            roots = roots.allow(&location.path, location.scope)?;
        }
        for (dir, scope) in &self.app_dirs {
            roots = roots.allow(dir, *scope)?;
        }
        for dir in &self.receipt_roots {
            roots = roots.allow(dir, Scope::System)?;
        }
        let r = &self.system_root;
        for denied in [
            r.join("System"),
            r.join("bin"),
            r.join("sbin"),
            r.join("usr/bin"),
            r.join("usr/sbin"),
            r.join("usr/lib"),
            r.join("usr/libexec"),
            r.join("usr/share"),
            r.join("usr/standalone"),
            r.join("private/etc"),
            r.join("private/var/db"),
            r.join("Library/Apple"),
        ] {
            roots = roots.deny(&denied)?;
        }
        for p in protected {
            roots = roots.protect(p)?;
        }
        Ok(roots)
    }
}

/// The canonical form of a path, or the path itself when it does not exist.
fn canonical(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}
