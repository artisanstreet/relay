//! Dev-only harness entry around the PRODUCTION Relay connector:
//! caller-built Hub/Store + `forge_http::account_service::serve_account_relay`.
//!
//! The Node harness (relay/integration/forge-smoke.test.ts) spawns this
//! binary, writes one JSON config line, and drives the initiator side over
//! the real Relay. No duplicated crypto, no app stand-ins: admission uses
//! fresh Core-issued machine grants, channels run production Noise confirm,
//! dispatch hits the real Hub/Store. Shutdown via a second stdin line.
//!
//! stdin:  {"ws_url": ..., "core_base_url": ..., "machine_id": ...,
//!          "account_id": ..., "machine_secret_hex": 64hex,
//!          "expected_iss": ..., "data_dir": ...}
//! stdout: {"ready": true} once serving (first connection attempt running)
//! stdin:  {"shutdown": true}
//! stdout: {"done": true} and exit 0. Fatal config errors exit 2.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

fn out_json(v: &serde_json::Value) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{v}");
    let _ = out.flush();
}

fn fail(msg: &str) -> ! {
    out_json(&serde_json::json!({ "fatal": msg }));
    std::process::exit(2);
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("RUST_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let cfg_line = match lines.next() {
        Some(Ok(l)) => l,
        _ => fail("missing config line"),
    };
    let cfg: serde_json::Value = match serde_json::from_str(&cfg_line) {
        Ok(v) => v,
        Err(e) => fail(&format!("bad config json: {e}")),
    };
    let get = |k: &str| {
        cfg.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| fail(&format!("missing config field {k}")))
            .to_owned()
    };
    let ws_url = get("ws_url");
    let core_base_url = get("core_base_url");
    let machine_id = get("machine_id");
    let account_id = get("account_id");
    let expected_iss = get("expected_iss");
    let data_dir = PathBuf::from(get("data_dir"));
    let secret_hex = get("machine_secret_hex");
    let secret_bytes = match hex::decode(&secret_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => fail("machine_secret_hex must be 64 hex chars"),
    };
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_bytes);

    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        fail(&format!("data dir: {e}"));
    }
    let store = match forge_store::Store::open(&data_dir) {
        Ok(s) => s,
        Err(e) => fail(&format!("open store: {e:?}")),
    };
    let engines = forge_engines::Engines::new(&data_dir);
    let hub = forge_runs::Hub::new(store, engines, data_dir);

    let config = forge_http::account_service::AccountRelayConfig {
        ws_url,
        core_base_url,
        machine_id,
        account_id,
        machine_secret: secret,
        expected_iss,
    };
    let shutdown = tokio_util::sync::CancellationToken::new();
    let worker_shutdown = shutdown.clone();
    let handle = tokio::spawn(async move {
        forge_http::account_service::serve_account_relay(config, hub, worker_shutdown).await;
    });
    out_json(&serde_json::json!({ "ready": true }));

    for line in lines {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("shutdown") == Some(&serde_json::Value::Bool(true)) {
            break;
        }
    }
    shutdown.cancel();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), handle).await;
    // Best-effort secret hygiene for a test binary.
    secret.fill(0);
    out_json(&serde_json::json!({ "done": true }));
}
