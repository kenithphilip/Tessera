use std::{env, fs, net::SocketAddr};

use serde_json::Value;
use tokio::net::TcpListener;

use tessera_gateway::{
    build_app, build_native_tls_server_config, GatewayConfig, GatewayConnectInfo, NativeTlsListener,
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

    let app = build_app(GatewayConfig {
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
    });

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
