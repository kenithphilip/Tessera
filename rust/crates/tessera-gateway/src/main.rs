use std::{env, fs, net::SocketAddr, sync::Arc, time::Duration};

use serde_json::Value;
use tokio::net::TcpListener;

// mimalloc as the global allocator. Drop-in win for tail latency
// under high concurrency: less fragmentation, better cache locality.
// `#[global_allocator]` must live in the crate that produces the
// final binary (the gateway), not in a library crate.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use tessera_gateway::{
    audit_log::JsonlHashchainSink,
    bootstrap_control_plane, build_app_with_state, build_native_tls_server_config, build_state,
    endpoints::{build_router as build_primitives_router, PrimitivesState},
    spawn_control_plane_sync_loop, GatewayConfig, GatewayConnectInfo, NativeTlsListener,
};

fn env_bool(name: &str) -> bool {
    matches!(
        env::var(name).ok().as_deref(),
        Some("1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON")
    )
}

fn env_csv(name: &str) -> Vec<String> {
    env::var(name)
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn env_trust_map(name: &str) -> std::collections::HashMap<String, i64> {
    let Some(raw) = env::var(name).ok() else {
        return std::collections::HashMap::new();
    };
    let parsed: Value =
        serde_json::from_str(&raw).expect("A2A required trust map must be valid JSON");
    let Some(entries) = parsed.as_object() else {
        panic!("A2A required trust map must be a JSON object");
    };
    entries
        .iter()
        .map(|(key, value)| {
            let trust = value
                .as_i64()
                .unwrap_or_else(|| panic!("A2A required trust for {key:?} must be an integer"));
            (key.clone(), trust)
        })
        .collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = env::var("TESSERA_GATEWAY_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("TESSERA_GATEWAY_PORT").unwrap_or_else(|_| "8081".to_string());
    let agent_id = env::var("TESSERA_AGENT_ID").ok();
    let agent_name =
        env::var("TESSERA_AGENT_NAME").unwrap_or_else(|_| "Tessera Gateway".to_string());
    let agent_description = env::var("TESSERA_AGENT_DESCRIPTION").ok();
    let agent_url = env::var("TESSERA_AGENT_URL").ok();
    let upstream_url = env::var("TESSERA_UPSTREAM_URL").ok();
    let a2a_upstream_url = env::var("TESSERA_A2A_UPSTREAM_URL").ok();
    let a2a_required_trust = env_trust_map("TESSERA_A2A_REQUIRED_TRUST_JSON");
    let policy_opa_url = env::var("TESSERA_POLICY_OPA_URL").ok();
    let policy_opa_path = env::var("TESSERA_POLICY_OPA_PATH")
        .unwrap_or_else(|_| "/v1/data/tessera/authz/allow".to_string());
    let policy_opa_token = env::var("TESSERA_POLICY_OPA_TOKEN").ok();
    let policy_fail_closed_backend_errors = !matches!(
        env::var("TESSERA_POLICY_FAIL_CLOSED_BACKEND_ERRORS")
            .ok()
            .as_deref(),
        Some("0" | "false" | "FALSE" | "no" | "NO" | "off" | "OFF")
    );
    let policy_include_provenance = !matches!(
        env::var("TESSERA_POLICY_INCLUDE_PROVENANCE")
            .ok()
            .as_deref(),
        Some("0" | "false" | "FALSE" | "no" | "NO" | "off" | "OFF")
    );
    let control_plane_url = env::var("TESSERA_CONTROL_PLANE_URL").ok();
    let control_plane_token = env::var("TESSERA_CONTROL_PLANE_TOKEN").ok();
    let control_plane_poll_interval = Duration::from_secs(
        env::var("TESSERA_CONTROL_PLANE_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(30),
    );
    let control_plane_hmac_key = env::var("TESSERA_CONTROL_PLANE_HMAC_KEY")
        .ok()
        .map(|value| value.into_bytes());
    let control_plane_heartbeat_identity_hs256_key =
        env::var("TESSERA_CONTROL_PLANE_HEARTBEAT_IDENTITY_HS256_KEY")
            .ok()
            .map(|value| value.into_bytes());
    let control_plane_heartbeat_use_spire =
        env_bool("TESSERA_CONTROL_PLANE_HEARTBEAT_SPIRE");
    let control_plane_heartbeat_spire_socket =
        env::var("TESSERA_CONTROL_PLANE_HEARTBEAT_SPIFFE_ENDPOINT_SOCKET").ok();
    let control_plane_heartbeat_spiffe_id =
        env::var("TESSERA_CONTROL_PLANE_HEARTBEAT_SPIFFE_ID").ok();
    let control_plane_heartbeat_identity_issuer =
        env::var("TESSERA_CONTROL_PLANE_HEARTBEAT_IDENTITY_ISSUER").ok();
    let control_plane_heartbeat_identity_audience =
        env::var("TESSERA_CONTROL_PLANE_HEARTBEAT_IDENTITY_AUDIENCE").ok();
    let control_plane_heartbeat_proof_private_key_pem =
        env::var("TESSERA_CONTROL_PLANE_HEARTBEAT_PROOF_PRIVATE_KEY_PEM")
            .ok()
            .map(|value| value.into_bytes());
    let control_plane_heartbeat_proof_public_jwk = env::var(
        "TESSERA_CONTROL_PLANE_HEARTBEAT_PROOF_PUBLIC_JWK_JSON",
    )
    .ok()
    .map(|value| {
        serde_json::from_str::<Value>(&value)
            .expect("control-plane heartbeat proof public JWK must be valid JSON")
    });
    let identity_hs256_key = env::var("TESSERA_IDENTITY_HS256_KEY")
        .ok()
        .map(|value| value.into_bytes());
    let identity_issuer = env::var("TESSERA_IDENTITY_ISSUER").ok();
    let identity_audience = env::var("TESSERA_IDENTITY_AUDIENCE").ok();
    let require_mtls = env_bool("TESSERA_REQUIRE_MTLS");
    let trust_xfcc = env_bool("TESSERA_TRUST_XFCC");
    let trusted_proxy_hosts = env_csv("TESSERA_TRUSTED_PROXY_HOSTS");
    let mtls_trust_domains = env_csv("TESSERA_MTLS_TRUST_DOMAINS");
    let tls_cert_path = env::var("TESSERA_TLS_CERT_PATH").ok();
    let tls_key_path = env::var("TESSERA_TLS_KEY_PATH").ok();
    let tls_client_ca_path = env::var("TESSERA_TLS_CLIENT_CA_PATH").ok();
    let native_tls_listener =
        tls_cert_path.is_some() || tls_key_path.is_some() || tls_client_ca_path.is_some();
    if native_tls_listener && (tls_cert_path.is_none() || tls_key_path.is_none()) {
        panic!("TESSERA_TLS_CERT_PATH and TESSERA_TLS_KEY_PATH are both required for native TLS");
    }
    let label_hmac_key = env::var("TESSERA_HMAC_KEY")
        .ok()
        .map(|value| value.into_bytes());
    let provenance_hmac_key = env::var("TESSERA_PROVENANCE_HMAC_KEY")
        .ok()
        .map(|value| value.into_bytes());
    let delegation_key = env::var("TESSERA_DELEGATION_KEY")
        .ok()
        .map(|value| value.into_bytes());
    let delegation_audience = env::var("TESSERA_DELEGATION_AUDIENCE").ok();

    let state = build_state(GatewayConfig {
        agent_id,
        agent_name,
        agent_description,
        agent_url,
        native_tls_listener,
        upstream_url,
        a2a_upstream_url,
        a2a_required_trust,
        policy_opa_url,
        policy_opa_path,
        policy_opa_token,
        policy_fail_closed_backend_errors,
        policy_include_provenance,
        control_plane_url,
        control_plane_token,
        control_plane_poll_interval,
        control_plane_hmac_key,
        control_plane_heartbeat_identity_hs256_key,
        control_plane_heartbeat_use_spire,
        control_plane_heartbeat_spire_socket,
        control_plane_heartbeat_spiffe_id,
        control_plane_heartbeat_identity_issuer,
        control_plane_heartbeat_identity_audience,
        control_plane_heartbeat_proof_private_key_pem,
        control_plane_heartbeat_proof_public_jwk,
        identity_hs256_key,
        identity_issuer,
        identity_audience,
        require_mtls,
        trust_xfcc,
        trusted_proxy_hosts,
        mtls_trust_domains,
        label_hmac_key,
        provenance_hmac_key,
        delegation_key,
        delegation_audience,
    })
    .map_err(std::io::Error::other)?;
    bootstrap_control_plane(&state)
        .await
        .map_err(std::io::Error::other)?;
    spawn_control_plane_sync_loop(state.clone());
    let chat_app = build_app_with_state(state);

    // Build the primitives router (new in v0.7.x): trust labels,
    // taint-tracking policy, per-session contexts, hash-chained audit
    // log, SSRF guard, URL rules. This sits alongside the chat /
    // A2A router on the same listener.
    let primitives_principal =
        env::var("TESSERA_PRINCIPAL").unwrap_or_else(|_| "tessera-gateway".to_string());
    let primitives_signing_key = env::var("TESSERA_HMAC_KEY")
        .ok()
        .map(String::into_bytes)
        .unwrap_or_else(|| b"tessera-gateway-default-key-rotate".to_vec());
    let mut primitives_state =
        PrimitivesState::with_signing_key(primitives_principal, primitives_signing_key);
    if let Ok(audit_path) = env::var("TESSERA_AUDIT_LOG_PATH") {
        let fsync_every = env::var("TESSERA_AUDIT_LOG_FSYNC_EVERY")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1);
        let seal_key = env::var("TESSERA_AUDIT_LOG_SEAL_KEY")
            .ok()
            .map(String::into_bytes);
        primitives_state.audit_seal_key = seal_key.clone();
        primitives_state.audit_sink = Some(Arc::new(
            JsonlHashchainSink::new(&audit_path, fsync_every, seal_key)
                .map_err(std::io::Error::other)?,
        ));
    }
    let primitives_router = build_primitives_router(Arc::new(primitives_state));
    let app = chat_app.merge(primitives_router);

    let addr: SocketAddr = format!("{host}:{port}").parse()?;
    let listener = TcpListener::bind(addr).await?;
    if native_tls_listener {
        let cert_pem = fs::read(
            tls_cert_path
                .as_deref()
                .expect("native TLS requires a server certificate path"),
        )?;
        let key_pem = fs::read(
            tls_key_path
                .as_deref()
                .expect("native TLS requires a server key path"),
        )?;
        let client_ca_pem = match tls_client_ca_path {
            Some(path) => Some(fs::read(path)?),
            None => None,
        };
        let server_config = build_native_tls_server_config(
            &cert_pem,
            &key_pem,
            client_ca_pem.as_deref(),
            require_mtls,
        )
        .map_err(std::io::Error::other)?;
        let tls_listener = NativeTlsListener::new(listener, server_config);
        axum::serve(
            tls_listener,
            app.into_make_service_with_connect_info::<GatewayConnectInfo>(),
        )
        .await?;
    } else {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    }
    Ok(())
}
