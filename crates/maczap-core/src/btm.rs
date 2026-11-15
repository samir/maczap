//! Background Task Management records, parsed from `sfltool dumpbtm` (readable
//! without root on macOS 26 — spike 0001 #7). Report-only (DESIGN §4.3).

use std::path::PathBuf;

use serde::Serialize;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct BtmRecord {
    pub uid: Option<i64>,
    pub name: String,
    pub kind: String,
    pub flags: String,
    pub disposition: String,
    pub identifier: String,
    pub team_id: Option<String>,
    pub bundle_id: Option<String>,
    pub parent_identifier: Option<String>,
    pub url: Option<String>,
    pub executable: Option<PathBuf>,
    pub associated_bundle_ids: Vec<String>,
}

impl BtmRecord {
    /// A legacy login item (shared file list), removable through System Events.
    pub fn is_legacy_login_item(&self) -> bool {
        self.kind.contains("login item") && self.flags.contains("legacy")
    }

    /// The file path behind the record's URL, if it is a `file://` URL.
    pub fn url_path(&self) -> Option<PathBuf> {
        let rest = self.url.as_deref()?.strip_prefix("file://")?;
        Some(PathBuf::from(percent_decode(rest)))
    }
}

pub fn parse(dump: &str) -> Vec<BtmRecord> {
    let mut records = Vec::new();
    let mut uid = None;
    let mut current: Option<BtmRecord> = None;
    for line in dump.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Records for UID ") {
            if let Some(r) = current.take() {
                records.push(r);
            }
            uid = rest.split_whitespace().next().and_then(|n| n.parse().ok());
            continue;
        }
        if trimmed.starts_with('#') && trimmed.ends_with(':') && !line.starts_with("    ") {
            if let Some(r) = current.take() {
                records.push(r);
            }
            current = Some(BtmRecord {
                uid,
                ..Default::default()
            });
            continue;
        }
        let Some(record) = current.as_mut() else {
            continue;
        };
        let Some((key, value)) = trimmed.split_once(": ") else {
            continue;
        };
        let value = value.trim().to_string();
        match key.trim() {
            "Name" => record.name = value,
            "Type" => record.kind = value,
            "Flags" => record.flags = value,
            "Disposition" => record.disposition = value,
            "Identifier" => record.identifier = value,
            "Team Identifier" => record.team_id = Some(value),
            "Bundle Identifier" => record.bundle_id = Some(value),
            "Parent Identifier" => record.parent_identifier = Some(value),
            "URL" if value != "(null)" => record.url = Some(value),
            "Executable Path" => record.executable = Some(PathBuf::from(value)),
            "Assoc. Bundle IDs" => {
                record.associated_bundle_ids = value
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            }
            _ => {}
        }
    }
    if let Some(r) = current.take() {
        records.push(r);
    }
    records
}

pub(crate) fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMP: &str = "\
========================
 Records for UID 0 : FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000
========================

 Items:

 #2:
                 UUID: 4D1E1D6B-0000-0000-0000-000000000000
                 Name: com.docker.vmnetd
                 Type: legacy daemon (0x10010)
                Flags: [ legacy, curated ] (0x5)
          Disposition: [enabled, allowed, notified] (0xb)
           Identifier: 16.com.docker.vmnetd
                  URL: file:///Library/LaunchDaemons/com.docker.vmnetd.plist
      Executable Path: /Library/PrivilegedHelperTools/com.docker.vmnetd
           Generation: 1
    Assoc. Bundle IDs: [ com.docker.docker ]
    Parent Identifier: Docker

========================
 Records for UID 501 : 5B2D4B41-5BBA-4E1E-9D34-BD986DB129B2
========================

 #30:
                 UUID: 92FB3BA0-E97C-4794-9C4D-A951BE8E10AB
                 Name: RectangleLauncher
       Developer Name: Ryan Hanson
      Team Identifier: XSYZ3E4B7D
                 Type: login item (0x4)
                Flags: [ sandboxed ] (0x40)
          Disposition: [disabled, allowed, notified] (0xa)
           Identifier: 4.com.knollsoft.RectangleLauncher
                  URL: Contents/Library/LoginItems/RectangleLauncher.app
           Generation: 2
    Bundle Identifier: com.knollsoft.RectangleLauncher
    Parent Identifier: 2.com.knollsoft.Rectangle

 #31:
                 Name: Rogue Amoeba Audio Capture Engine (ACE)
                 Type: developer (0x20)
                  URL: (null)
  Embedded Item Identifiers:
    #1: 16.com.rogueamoeba.aceagent
";

    #[test]
    fn parses_records_with_their_uid_and_fields() {
        let records = parse(DUMP);
        assert_eq!(records.len(), 3, "{records:#?}");
        let docker = &records[0];
        assert_eq!(docker.uid, Some(0));
        assert_eq!(docker.associated_bundle_ids, vec!["com.docker.docker"]);
        assert_eq!(
            docker.executable,
            Some(PathBuf::from(
                "/Library/PrivilegedHelperTools/com.docker.vmnetd"
            ))
        );
        assert_eq!(
            docker.url_path(),
            Some(PathBuf::from(
                "/Library/LaunchDaemons/com.docker.vmnetd.plist"
            ))
        );
        let launcher = &records[1];
        assert_eq!(launcher.uid, Some(501));
        assert_eq!(
            launcher.bundle_id.as_deref(),
            Some("com.knollsoft.RectangleLauncher")
        );
        assert_eq!(
            launcher.parent_identifier.as_deref(),
            Some("2.com.knollsoft.Rectangle")
        );
        assert_eq!(launcher.team_id.as_deref(), Some("XSYZ3E4B7D"));
        assert!(!launcher.is_legacy_login_item());
        assert_eq!(
            records[2].url, None,
            "(null) URLs are dropped; embedded items are not records"
        );
    }

    #[test]
    fn decodes_percent_escaped_file_urls() {
        let record = BtmRecord {
            url: Some("file:///Applications/My%20App.app/".into()),
            ..Default::default()
        };
        assert_eq!(
            record.url_path(),
            Some(PathBuf::from("/Applications/My App.app/"))
        );
    }
}
