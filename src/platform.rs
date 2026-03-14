//! Platform-specific binary resolution.
//!
//! Launchd daemons run with a minimal PATH (only nix store paths).
//! System binaries live at platform-specific locations that aren't
//! in PATH. This module provides a single resolution point so
//! collectors don't hardcode paths.

/// Resolve the absolute path to a system binary.
///
/// On macOS, system binaries live under `/usr/sbin` or `/usr/bin`.
/// Falls back to bare name (relies on PATH) on unknown platforms.
pub fn system_bin(name: &str) -> &'static str {
    match name {
        "arp" => "/usr/sbin/arp",
        "netstat" => "/usr/sbin/netstat",
        "scutil" => "/usr/sbin/scutil",
        "ifconfig" => "/sbin/ifconfig",
        "route" => "/usr/sbin/route",
        "networksetup" => "/usr/sbin/networksetup",
        "host" => "/usr/bin/host",
        _ => {
            // Leak intentionally — these are process-lifetime constants.
            // Only called for a small fixed set of system tools.
            Box::leak(name.to_string().into_boxed_str())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_binaries_have_absolute_paths() {
        assert!(system_bin("arp").starts_with('/'));
        assert!(system_bin("netstat").starts_with('/'));
        assert!(system_bin("scutil").starts_with('/'));
    }

    #[test]
    fn unknown_binary_returns_bare_name() {
        assert_eq!(system_bin("some_tool"), "some_tool");
    }
}
