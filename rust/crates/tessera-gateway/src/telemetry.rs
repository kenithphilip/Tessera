//! Tracing initialization for the gateway binary.
//!
//! Two paths:
//!
//! - Default (feature `otel` off): plain `tracing-subscriber` with
//!   the `RUST_LOG` env filter, formatted to stderr. No external
//!   dependencies, zero config.
//! - `otel` feature on: the same fmt subscriber plus an
//!   OpenTelemetry tracer that exports spans via OTLP gRPC.
//!   Operators configure with the standard OTel env vars
//!   (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, etc.).
//!
//! `tower_http::trace::TraceLayer::new_for_http()` is already in
//! the gateway's `build_app_with_state`; this module just decides
//! where those spans are exported.

use std::sync::Once;

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

static INIT: Once = Once::new();

/// Default tracing setup: env-filtered `tracing-subscriber` with
/// the standard fmt layer to stderr. Idempotent: subsequent calls
/// after the first are no-ops, so it is safe to call from `main`
/// and from integration tests.
pub fn init_tracing() {
    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info"));
        let registry = tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr));

        #[cfg(feature = "otel")]
        let registry = registry.with(otel::layer());

        registry.init();

        #[cfg(feature = "otel")]
        otel::log_active_exporter();
    });
}

#[cfg(feature = "otel")]
mod otel {
    //! OTel exporter wired up via the standard env-var contract.
    //!
    //! `OTEL_EXPORTER_OTLP_ENDPOINT` (default
    //! `http://localhost:4317`), `OTEL_SERVICE_NAME` (default
    //! `tessera-gateway`), and the rest of the OTel SDK env vars
    //! all work as documented at
    //! <https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/>.

    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry::KeyValue;
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::Resource;
    use tracing_opentelemetry::OpenTelemetryLayer;
    use tracing_subscriber::registry::LookupSpan;

    pub(super) fn layer<S>() -> impl tracing_subscriber::Layer<S> + Send + Sync + 'static
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a> + Send + Sync,
    {
        let service_name = std::env::var("OTEL_SERVICE_NAME")
            .unwrap_or_else(|_| "tessera-gateway".to_string());
        let exporter = opentelemetry_otlp::new_exporter().tonic().with_endpoint(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:4317".to_string()),
        );
        let provider = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(exporter)
            .with_trace_config(
                opentelemetry_sdk::trace::Config::default().with_resource(Resource::new(vec![
                    KeyValue::new("service.name", service_name),
                ])),
            )
            .install_batch(opentelemetry_sdk::runtime::Tokio)
            .expect("OTLP tracing pipeline installs");
        // `install_batch` returns a TracerProvider; OpenTelemetryLayer
        // wants a Tracer (only the Tracer impls `PreSampledTracer`).
        // Fetch a named Tracer off the provider and wrap that.
        let tracer = provider.tracer("tessera-gateway");
        OpenTelemetryLayer::new(tracer)
    }

    pub(super) fn log_active_exporter() {
        let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:4317".to_string());
        eprintln!("tessera-gateway: OTLP exporter active, endpoint={endpoint}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_tracing_is_idempotent() {
        // Calling twice must not panic; the Once guard ensures the
        // global subscriber is installed exactly once.
        init_tracing();
        init_tracing();
    }
}
