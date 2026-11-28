pub mod api;
pub mod logging;
pub mod ping;
pub mod srp;
pub mod storage;
pub mod updater;
pub mod wg;

/// Application version string for Freeton VPN.
pub const APP_VERSION: &str = "3.1.0";

/// Application display name for Freeton VPN.
pub const APP_NAME: &str = "Freeton VPN";

#[cfg(test)]
mod tests {
    #[test]
    fn workspace_version_matches_major_three() {
        assert!(crate::APP_VERSION.starts_with("3."));
    }
}
