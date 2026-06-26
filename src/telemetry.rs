//! Tracing / logging setup.

pub fn init() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("issuer_backend=debug,tower_http=info,info"));
    // Logs go to stderr so stdout stays clean for command output
    // (e.g. the `issue-test` subcommand prints the credential to stdout).
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
