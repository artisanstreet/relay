//! Dev-only NATIVE Relay client proof: the actual
//! `artisan_account::relay_client::RelayClient` (the same transport behind
//! `editor_core::ForgeClient::via_relay`) against the live Core + workerd
//! Relay + production Forge connector.
//!
//! The Node harness spawns this binary, writes one JSON config line, and
//! reads JSON result lines. Plain `fn main` driving one explicit
//! `Runtime::block_on`: this proves the live client path end to end, but
//! `block_on` DOES provide a reactor inside `run` — so this binary is live
//! proof, not no-reactor proof. The no-ambient-reactor entry is covered by
//! `editor_core`'s `relay_dial_without_tokio_reactor_fails_with_
//! connection_refused` test, which polls the real dialer from a GPUI
//! executor with no Tokio runtime in scope.
//!
//! stdin:  {"relay_base_url": ..., "core_base_url": ..., "account_id": ...,
//!          "machine_id": ..., "forge_ed25519_b64u": ..., "grant_jwt": ...,
//!          "cnf_secret_hex": 64hex, "session_token": ..., "draft_scope": ...}
//! stdout: {"ok": true, "state_head": N, "stream": id, "draft_bytes": N}
//!         or {"fatal": msg} with exit 2.

use std::io::{self, BufRead, Write};

fn out_json(v: &serde_json::Value) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{v}");
    let _ = out.flush();
}

fn fail(msg: &str) -> ! {
    out_json(&serde_json::json!({ "fatal": msg }));
    std::process::exit(2);
}

fn main() {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("native-smoke")
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => fail(&format!("runtime: {e}")),
    };
    // block_on provides the reactor for `run`; the GPUI-entry posture
    // (no ambient reactor at the call site) is covered by the editor-core
    // executor regression test, not here.
    let code = runtime.block_on(run());
    std::process::exit(code);
}

async fn run() -> i32 {
    let cfg_line = {
        let stdin = io::stdin();
        match stdin.lock().lines().next() {
            Some(Ok(l)) => l,
            _ => {
                out_json(&serde_json::json!({ "fatal": "missing config line" }));
                return 2;
            }
        }
    };
    let cfg: serde_json::Value = match serde_json::from_str(&cfg_line) {
        Ok(v) => v,
        Err(e) => {
            out_json(&serde_json::json!({ "fatal": format!("bad config json: {e}") }));
            return 2;
        }
    };
    let get = |k: &str| {
        cfg.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned()
    };
    let relay_base_url = get("relay_base_url");
    let core_base_url = get("core_base_url");
    let account_id = get("account_id");
    let machine_id = get("machine_id");
    let forge_key = get("forge_ed25519_b64u");
    let grant_jwt = get("grant_jwt");
    let session_token = get("session_token");
    let draft_scope = get("draft_scope");
    for (key, value) in [
        ("relay_base_url", &relay_base_url),
        ("core_base_url", &core_base_url),
        ("account_id", &account_id),
        ("machine_id", &machine_id),
        ("forge_ed25519_b64u", &forge_key),
        ("grant_jwt", &grant_jwt),
        ("session_token", &session_token),
        ("draft_scope", &draft_scope),
    ] {
        if value.is_empty() {
            out_json(&serde_json::json!({ "fatal": format!("missing config field {key}") }));
            return 2;
        }
    }
    let secret_hex = get("cnf_secret_hex");
    let secret_bytes = match hex::decode(&secret_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            out_json(&serde_json::json!({ "fatal": "cnf_secret_hex must be 64 hex chars" }));
            return 2;
        }
    };
    let mut cnf_secret = [0u8; 32];
    cnf_secret.copy_from_slice(&secret_bytes);

    let outcome = run_inner(
        &relay_base_url,
        &core_base_url,
        &account_id,
        &machine_id,
        &forge_key,
        &grant_jwt,
        &cnf_secret,
        &session_token,
        &draft_scope,
    )
    .await;
    cnf_secret.fill(0);
    match outcome {
        Ok(summary) => {
            out_json(&summary);
            0
        }
        Err(e) => {
            out_json(&serde_json::json!({ "fatal": format!("{e:#}") }));
            2
        }
    }
}

async fn run_inner(
    relay_base_url: &str,
    core_base_url: &str,
    account_id: &str,
    machine_id: &str,
    forge_key: &str,
    grant_jwt: &str,
    cnf_secret: &[u8; 32],
    session_token: &str,
    draft_scope: &str,
) -> anyhow::Result<serde_json::Value> {
    use anyhow::Context as _;

    let core = artisan_account::CoreSessionClient::new(core_base_url)
        .map_err(|e| anyhow::anyhow!("core client: {e:?}"))?;
    let session = artisan_account::SessionToken::new(session_token.to_owned());

    // 1. Dial: admission, Noise XX, JWT-in-confirm verified against the
    //    enrolled Forge key — the production path, no stand-ins.
    let client = artisan_account::RelayClient::connect(
        relay_base_url,
        account_id,
        machine_id,
        grant_jwt,
        cnf_secret,
        forge_key,
        core,
        session,
    )
    .await
    .context("native dial")?;

    // 2. Unary /state through the tunnel.
    let state: serde_json::Value = client
        .request_json("GET", "/state", None)
        .await
        .context("native /state")?;
    let protocol = state.get("protocol").and_then(|v| v.as_u64()).unwrap_or(0);
    if protocol != u64::from(artisan_api::PROTOCOL_VERSION) {
        anyhow::bail!("protocol mismatch: forge={protocol}");
    }
    let head = state.get("head").and_then(|v| v.as_u64()).unwrap_or(0);
    if !state.get("projects").is_some_and(|v| v.is_array()) {
        anyhow::bail!("state has no projects array");
    }

    // 3. Event subscription: first envelope must be Hello.
    let mut stream = client
        .subscribe("/events?since=0")
        .await
        .context("native subscribe")?;
    let stream_id = stream.stream_id().clone();
    if stream_id.is_empty() {
        anyhow::bail!("empty stream id");
    }
    let hello = stream
        .next_event()
        .await
        .context("native hello")?
        .context("stream ended before hello")?;
    match &hello.event {
        artisan_api::Event::Hello { protocol, .. } => {
            if *protocol != artisan_api::PROTOCOL_VERSION {
                anyhow::bail!("event protocol mismatch");
            }
        }
        other => anyhow::bail!("first event is not hello: {}", event_type(other)),
    }

    // 4. >1 MiB roundtrip through the real draft store: PUT then GET with
    //    exact full-text compare after TunnelChunk reassembly.
    let big_text = "0123456789ABCDEF".repeat(131_072);
    if big_text.len() != 2 * 1024 * 1024 {
        anyhow::bail!("bad fixture size");
    }
    let put: serde_json::Value = client
        .request_json(
            "PUT",
            &format!("/drafts/{draft_scope}"),
            Some(serde_json::json!({
                "expected_revision": 0,
                "body": { "text": &big_text },
            })),
        )
        .await
        .context("native draft PUT")?;
    if put.get("saved") != Some(&serde_json::Value::Bool(true)) {
        anyhow::bail!("draft PUT not saved: {put}");
    }
    let got: serde_json::Value = client
        .request_json("GET", &format!("/drafts/{draft_scope}"), None)
        .await
        .context("native draft GET")?;
    let text = got
        .pointer("/body/text")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if text != big_text {
        anyhow::bail!("draft text mismatch: {} != {}", text.len(), big_text.len());
    }

    // 5. Clean unsubscribe.
    stream.unsubscribe().await.context("native unsubscribe")?;

    Ok(serde_json::json!({
        "ok": true,
        "state_head": head,
        "stream": stream_id,
        "draft_bytes": big_text.len(),
    }))
}

fn event_type(event: &artisan_api::Event) -> &'static str {
    match event {
        artisan_api::Event::Hello { .. } => "hello",
        artisan_api::Event::Project { .. } => "project",
        artisan_api::Event::Thread { .. } => "thread",
        artisan_api::Event::Item { .. } => "item",
        artisan_api::Event::Run { .. } => "run",
        artisan_api::Event::ItemState { .. } => "item-state",
        artisan_api::Event::Setting { .. } => "setting",
        artisan_api::Event::Live { .. } => "live",
        artisan_api::Event::Suggestion { .. } => "suggestion",
        artisan_api::Event::Engine { .. } => "engine",
        artisan_api::Event::EngineInstall { .. } => "engine-install",
        artisan_api::Event::EditorCall { .. } => "editor-call",
        artisan_api::Event::Reset => "reset",
    }
}
