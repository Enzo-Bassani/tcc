//! `wallet-conformance` — the CLI the Kotlin conformance test drives.
//!
//! Two subcommands wrap [`wallet_core::mint_bundle`] / [`wallet_core::verify_bundle`]:
//!
//! ```text
//! wallet-conformance mint   --holder-jwk <pub.json> [--out <bundle.json>] [--revoked]
//! wallet-conformance verify --bundle <bundle.json>  --response <response.json>
//! ```
//!
//! The `mint` subcommand reads the wallet's public holder JWK and writes a
//! [`Bundle`] (credential + signed request + verifier documents). The wallet then
//! verifies the bundle's signed request, builds a VP Token, and JWE-encrypts it as
//! the Authorization Response. The `verify` subcommand runs the real verifier over
//! that response (re-verifying the request, decrypting, validating) and exits `0`
//! iff the report is `valid` (printing the report JSON either way), so a test can
//! simply assert on the process exit code.

use std::collections::HashMap;
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use wallet_core::{Bundle, mint_bundle, verify_bundle};

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("wallet-conformance: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, rest) = args
        .split_first()
        .ok_or_else(|| anyhow!("usage: wallet-conformance <mint|verify> [options]"))?;

    match cmd.as_str() {
        "mint" => cmd_mint(rest),
        "verify" => cmd_verify(rest),
        other => bail!("unknown subcommand '{other}' (expected 'mint' or 'verify')"),
    }
}

fn cmd_mint(args: &[String]) -> Result<ExitCode> {
    let opts = Options::parse(args);
    let holder_path = opts.get("holder-jwk").context("--holder-jwk <path> is required")?;
    let holder_jwk: Value =
        serde_json::from_str(&read(holder_path)?).context("parsing --holder-jwk as JSON")?;

    let bundle = mint_bundle(&holder_jwk, opts.flag("revoked"));
    let json = serde_json::to_string_pretty(&bundle)?;
    match opts.get("out") {
        Some(path) => std::fs::write(path, json).with_context(|| format!("writing {path}"))?,
        None => println!("{json}"),
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_verify(args: &[String]) -> Result<ExitCode> {
    let opts = Options::parse(args);
    let bundle_path = opts.get("bundle").context("--bundle <path> is required")?;
    let response_path = opts.get("response").context("--response <path> is required")?;

    let bundle: Bundle = serde_json::from_str(&read(bundle_path)?).context("parsing --bundle")?;
    let response: Value =
        serde_json::from_str(&read(response_path)?).context("parsing --response")?;

    let report = verify_bundle(&bundle, &response);
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(if report.valid {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn read(path: &str) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("reading {path}"))
}

/// A tiny `--key value` / `--flag` parser (kept dependency-free, matching the
/// project's preference for small self-contained code).
struct Options {
    values: HashMap<String, String>,
    flags: Vec<String>,
}

impl Options {
    fn parse(args: &[String]) -> Self {
        let mut values = HashMap::new();
        let mut flags = Vec::new();
        let mut i = 0;
        while i < args.len() {
            if let Some(name) = args[i].strip_prefix("--") {
                match args.get(i + 1) {
                    Some(v) if !v.starts_with("--") => {
                        values.insert(name.to_string(), v.clone());
                        i += 2;
                    }
                    _ => {
                        flags.push(name.to_string());
                        i += 1;
                    }
                }
            } else {
                i += 1;
            }
        }
        Self { values, flags }
    }

    fn get(&self, name: &str) -> Option<&String> {
        self.values.get(name)
    }

    fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f == name)
    }
}
