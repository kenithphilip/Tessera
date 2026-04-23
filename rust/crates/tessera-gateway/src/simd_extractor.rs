//! SIMD-accelerated JSON body extractor for axum handlers.
//!
//! Drop-in replacement for [`axum::Json`] that parses request bodies
//! with [`simd_json`]. Falls back to [`serde_json`] on any parse
//! error, so behavior on edge cases stays identical to the stock
//! extractor while the happy path benefits from SIMD parsing on
//! aarch64 + x86_64.
//!
//! The fallback path is intentional: simd_json is stricter than
//! serde_json on a few corner cases (trailing whitespace, certain
//! NaN encodings). Falling back rather than rejecting means we keep
//! every existing handler test green while still getting the SIMD
//! speedup on the 99% of well-formed bodies.
//!
//! Usage:
//!
//! ```rust,ignore
//! use tessera_gateway::simd_extractor::SimdJson;
//!
//! async fn handler(SimdJson(body): SimdJson<MyType>) -> ... { ... }
//! ```

use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;

/// Tagged-union extractor: parses the request body as JSON via
/// [`simd_json`] first, falls back to [`serde_json`] on error.
///
/// The wrapped value `T` must implement [`DeserializeOwned`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SimdJson<T>(pub T);

impl<T, S> FromRequest<S> for SimdJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = SimdJsonRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        // Reject obviously wrong content-types early. axum's stock
        // Json does the same; we mirror to avoid silent acceptance
        // of form-urlencoded bodies etc.
        if let Some(ct) = req.headers().get(header::CONTENT_TYPE) {
            let ct_bytes = ct.as_bytes();
            // Accept "application/json", "application/json;charset=utf-8",
            // and the */*+json convention. Reject everything else.
            let looks_like_json = ct_bytes
                .windows(b"json".len())
                .any(|w| w.eq_ignore_ascii_case(b"json"));
            if !looks_like_json {
                return Err(SimdJsonRejection::UnsupportedMediaType);
            }
        }

        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|e| SimdJsonRejection::BodyRead(e.to_string()))?;

        // Empty body is rejected uniformly. Both parsers would accept
        // `null` here, but a zero-byte body is almost always a client
        // bug; surface it.
        if bytes.is_empty() {
            return Err(SimdJsonRejection::EmptyBody);
        }

        // simd_json mutates the buffer in place, so we need a Vec.
        // Bytes::to_vec is the only allocation on the hot path.
        let mut buf = bytes.to_vec();

        match simd_json::serde::from_slice::<T>(&mut buf) {
            Ok(value) => Ok(Self(value)),
            Err(simd_err) => {
                // Fall back to serde_json. We re-borrow the original
                // immutable bytes because simd_json scribbled on `buf`.
                match serde_json::from_slice::<T>(&bytes) {
                    Ok(value) => {
                        tracing::debug!(
                            simd_err = %simd_err,
                            "simd-json rejected body, serde_json accepted; using fallback"
                        );
                        Ok(Self(value))
                    }
                    Err(serde_err) => Err(SimdJsonRejection::Parse(serde_err.to_string())),
                }
            }
        }
    }
}

/// Failure modes for [`SimdJson`].
#[derive(Debug)]
pub enum SimdJsonRejection {
    UnsupportedMediaType,
    EmptyBody,
    BodyRead(String),
    Parse(String),
}

impl IntoResponse for SimdJsonRejection {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::UnsupportedMediaType => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Content-Type must be application/json".to_owned(),
            ),
            Self::EmptyBody => (
                StatusCode::BAD_REQUEST,
                "Request body must not be empty".to_owned(),
            ),
            Self::BodyRead(e) => (
                StatusCode::BAD_REQUEST,
                format!("Failed to read request body: {e}"),
            ),
            Self::Parse(e) => (
                StatusCode::BAD_REQUEST,
                format!("Failed to parse JSON body: {e}"),
            ),
        };
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Probe {
        tool: String,
        count: i64,
    }

    fn json_request(body: &'static str) -> Request {
        HttpRequest::builder()
            .method("POST")
            .uri("/")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn happy_path_simd_parses_body() {
        let req = json_request(r#"{"tool":"send_email","count":3}"#);
        let SimdJson(parsed): SimdJson<Probe> =
            SimdJson::from_request(req, &()).await.unwrap();
        assert_eq!(
            parsed,
            Probe {
                tool: "send_email".to_owned(),
                count: 3
            }
        );
    }

    #[tokio::test]
    async fn rejects_wrong_content_type() {
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(r#"{"tool":"x","count":1}"#))
            .unwrap();
        let r: Result<SimdJson<Probe>, _> = SimdJson::from_request(req, &()).await;
        assert!(matches!(r, Err(SimdJsonRejection::UnsupportedMediaType)));
    }

    #[tokio::test]
    async fn rejects_empty_body() {
        let req = json_request("");
        let r: Result<SimdJson<Probe>, _> = SimdJson::from_request(req, &()).await;
        assert!(matches!(r, Err(SimdJsonRejection::EmptyBody)));
    }

    #[tokio::test]
    async fn rejects_unparseable_body_after_fallback() {
        let req = json_request(r#"{not even close to json"#);
        let r: Result<SimdJson<Probe>, _> = SimdJson::from_request(req, &()).await;
        assert!(matches!(r, Err(SimdJsonRejection::Parse(_))));
    }

    #[tokio::test]
    async fn accepts_application_json_with_charset() {
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/")
            .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
            .body(Body::from(r#"{"tool":"x","count":1}"#))
            .unwrap();
        let SimdJson(parsed): SimdJson<Probe> =
            SimdJson::from_request(req, &()).await.unwrap();
        assert_eq!(parsed.tool, "x");
        assert_eq!(parsed.count, 1);
    }

    #[tokio::test]
    async fn accepts_vendor_plus_json() {
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/")
            .header(header::CONTENT_TYPE, "application/vnd.tessera.v1+json")
            .body(Body::from(r#"{"tool":"x","count":1}"#))
            .unwrap();
        let SimdJson(parsed): SimdJson<Probe> =
            SimdJson::from_request(req, &()).await.unwrap();
        assert_eq!(parsed.tool, "x");
    }

    #[tokio::test]
    async fn handles_large_body_via_simd_path() {
        // 64KB worth of payload: well above L1 cache, exercises the
        // SIMD path's main appeal.
        let mut s = String::from(r#"{"tool":"big","count":42,"pad":""#);
        s.push_str(&"a".repeat(64 * 1024));
        s.push_str(r#""}"#);
        let body = Box::leak(s.into_boxed_str()) as &'static str;
        let req = json_request(body);

        #[derive(Debug, Deserialize)]
        struct Big {
            tool: String,
            count: i64,
            #[allow(dead_code)]
            pad: String,
        }
        let SimdJson(parsed): SimdJson<Big> =
            SimdJson::from_request(req, &()).await.unwrap();
        assert_eq!(parsed.tool, "big");
        assert_eq!(parsed.count, 42);
    }
}
