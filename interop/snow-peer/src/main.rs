//! Live interop peer for the Relay noise channel contract.
//!
//! Implements the RESPONDER side of `Noise_XX_25519_ChaChaPoly_BLAKE2b`
//! with the established `snow` crate, driven over JSON lines on stdio by
//! the Node test harness (test/noise-interop.test.ts).
//!
//! Usage: snow-peer <static-priv-hex> <prologue-hex>
//! stdin:  {"m1": hex} -> stdout {"m2": hex}
//!         {"m3": hex} -> stdout {"hash": hex}   (handshake done)
//!         {"ct": hex} -> stdout {"pt": hex}     (transport responder->? no:
//!                                                decrypt initiator->responder)
//!         {"send": hex} -> stdout {"ct": hex}   (transport responder->initiator)
//! Errors: {"error": "..."} (handshake/transport failure — the interop
//!         negative assertions depend on these, do not swallow them).

use std::io::{self, BufRead, Write};

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2b";
const MAXMSG: usize = 65535;

fn err(msg: String) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{}", serde_json::json!({ "error": msg }));
    let _ = out.flush();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: snow-peer <static-priv-hex> <prologue-hex>");
        std::process::exit(2);
    }
    let privkey = match hex::decode(&args[1]) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            eprintln!("bad static privkey");
            std::process::exit(2);
        }
    };
    let prologue = match hex::decode(&args[2]) {
        Ok(b) => b,
        _ => {
            eprintln!("bad prologue");
            std::process::exit(2);
        }
    };

    let params: snow::params::NoiseParams = match NOISE_PARAMS.parse() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("bad params: {e:?}");
            std::process::exit(2);
        }
    };
    fn build(params: snow::params::NoiseParams, privkey: &[u8], prologue: &[u8]) -> Result<snow::HandshakeState, snow::Error> {
        Ok(snow::Builder::new(params)
            .local_private_key(privkey)?
            .prologue(prologue)?
            .build_responder()?)
    }
    let mut hs = match build(params, &privkey, &prologue) {
        Err(e) => {
            eprintln!("build failed: {e:?}");
            std::process::exit(2);
        }
        Ok(h) => h,
    };

    let stdin = io::stdin();
    let mut transport: Option<snow::TransportState> = None;
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                err(format!("bad json: {e}"));
                continue;
            }
        };
        let mut out = io::stdout().lock();
        if let Some(m1) = v.get("m1").and_then(|x| x.as_str()) {
            let msg = match hex::decode(m1) {
                Ok(b) => b,
                Err(e) => {
                    err(format!("bad m1 hex: {e}"));
                    continue;
                }
            };
            let mut payload = [0u8; MAXMSG];
            if let Err(e) = hs.read_message(&msg, &mut payload) {
                err(format!("m1 rejected: {e:?}"));
                continue;
            }
            let mut reply = [0u8; MAXMSG];
            match hs.write_message(&[], &mut reply) {
                Ok(n) => {
                    let _ = writeln!(out, "{}", serde_json::json!({ "m2": hex::encode(&reply[..n]) }));
                }
                Err(e) => err(format!("m2 failed: {e:?}")),
            }
        } else if let Some(m3) = v.get("m3").and_then(|x| x.as_str()) {
            let msg = match hex::decode(m3) {
                Ok(b) => b,
                Err(e) => {
                    err(format!("bad m3 hex: {e}"));
                    continue;
                }
            };
            let mut payload = [0u8; MAXMSG];
            if let Err(e) = hs.read_message(&msg, &mut payload) {
                err(format!("m3 rejected: {e:?}"));
                continue;
            }
            if !hs.is_handshake_finished() {
                err("handshake not finished after m3".to_string());
                continue;
            }
            let hash = hex::encode(hs.get_handshake_hash());
            match hs.into_transport_mode() {
                Ok(t) => {
                    transport = Some(t);
                    let _ = writeln!(out, "{}", serde_json::json!({ "hash": hash }));
                }
                Err(e) => err(format!("transport failed: {e:?}")),
            }
            break;
        } else {
            err("unknown command (expected m1 or m3)".to_string());
        }
        let _ = out.flush();
    }

    // Transport phase: decrypt {"ct"} -> {"pt"}, encrypt {"send"} -> {"ct"}.
    let mut t = match transport {
        Some(t) => t,
        None => return,
    };
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                err(format!("bad json: {e}"));
                continue;
            }
        };
        let mut out = io::stdout().lock();
        if let Some(ct) = v.get("ct").and_then(|x| x.as_str()) {
            let msg = match hex::decode(ct) {
                Ok(b) => b,
                Err(e) => {
                    err(format!("bad ct hex: {e}"));
                    continue;
                }
            };
            let mut pt = [0u8; MAXMSG];
            match t.read_message(&msg, &mut pt) {
                Ok(n) => {
                    let _ = writeln!(out, "{}", serde_json::json!({ "pt": hex::encode(&pt[..n]) }));
                }
                Err(e) => err(format!("decrypt failed: {e:?}")),
            }
        } else if let Some(send) = v.get("send").and_then(|x| x.as_str()) {
            let pt = match hex::decode(send) {
                Ok(b) => b,
                Err(e) => {
                    err(format!("bad send hex: {e}"));
                    continue;
                }
            };
            let mut ct = [0u8; MAXMSG];
            match t.write_message(&pt, &mut ct) {
                Ok(n) => {
                    let _ = writeln!(out, "{}", serde_json::json!({ "ct": hex::encode(&ct[..n]) }));
                }
                Err(e) => err(format!("encrypt failed: {e:?}")),
            }
        } else {
            err("unknown command (expected ct or send)".to_string());
        }
        let _ = out.flush();
    }
}
