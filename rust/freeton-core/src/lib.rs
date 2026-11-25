/// Application version string for Freeton VPN.
pub const APP_VERSION: &str = "3.0.0";

/// Application display name for Freeton VPN.
pub const APP_NAME: &str = "Freeton VPN";

#[cfg(test)]
mod tests {
    #[test]
    fn workspace_version_matches_major_three() {
        assert!(crate::APP_VERSION.starts_with("3."));
    }
}
