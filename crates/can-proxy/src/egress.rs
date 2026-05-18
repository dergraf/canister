use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::header::{HOST, TE, TRANSFER_ENCODING};
use hyper::{Request, Response};
#[cfg(feature = "experimental-h2c")]
use hyper_util::rt::TokioIo;
#[cfg(feature = "experimental-h2c")]
use tracing::error;
use tracing::warn;

/// Header the sandboxed worker used to be able to set to switch the proxy's
/// upstream scheme. Now ignored — kept as a constant for the
/// `client_header_ignored` warning log.
const LEGACY_SCHEME_HEADER: &str = "x-canister-upstream-scheme";

pub fn build_upstream_uri<B>(
    req: &Request<B>,
    host: &str,
    default_scheme: &'static str,
    recipe_scheme: Option<&str>,
) -> Result<(hyper::Uri, String), String> {
    // Refuse to be steered by a client-controlled header. The sandboxed
    // process can no longer pick `h2c` (or anything else) by setting
    // `x-canister-upstream-scheme` — that's a recipe-level decision now
    // (R11 in the DLP plan). If we see the header, log a warning so the
    // configurer notices their app is trying to use the old mechanism.
    if req.headers().contains_key(LEGACY_SCHEME_HEADER) {
        warn!(
            "ignoring client-supplied {} header; set [proxy] upstream_scheme in the recipe instead",
            LEGACY_SCHEME_HEADER
        );
    }

    let inferred = req.uri().scheme_str().unwrap_or(default_scheme);
    let original_scheme = recipe_scheme.unwrap_or(inferred).to_string();

    let authority = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| {
            req.headers()
                .get(HOST)
                .and_then(|h| h.to_str().ok())
                .map(str::to_string)
        })
        .unwrap_or_else(|| host.to_string());
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let scheme = if original_scheme == "h2c" {
        "http"
    } else {
        inferred
    };

    let uri = format!("{}://{}{}", scheme, authority, path_and_query)
        .parse::<hyper::Uri>()
        .map_err(|err| format!("failed to build upstream URI: {err}"))?;
    Ok((uri, original_scheme))
}

pub fn sanitize_h2c_headers(req: &mut Request<BoxBody<Bytes, hyper::Error>>) {
    req.headers_mut().remove(hyper::header::CONNECTION);
    req.headers_mut().remove("proxy-connection");
    req.headers_mut().remove("keep-alive");
    req.headers_mut().remove("http2-settings");
    req.headers_mut().remove(hyper::header::UPGRADE);
    req.headers_mut().remove(HOST);
    if req.headers().get(TE).is_some_and(|v| v != "trailers") {
        req.headers_mut().remove(TE);
    }
    req.headers_mut().remove(TRANSFER_ENCODING);
    *req.version_mut() = hyper::Version::HTTP_2;
}

#[cfg(feature = "experimental-h2c")]
pub async fn forward_h2c_request(
    req: Request<BoxBody<Bytes, hyper::Error>>,
) -> Result<Response<hyper::body::Incoming>, String> {
    let host = req
        .uri()
        .host()
        .ok_or_else(|| "missing host for h2c request".to_string())?
        .to_string();
    let port = req.uri().port_u16().unwrap_or(80);

    let stream = tokio::net::TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| format!("h2c connect failed: {e}"))?;
    let io = TokioIo::new(stream);

    let (mut sender, conn) =
        hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .handshake(io)
            .await
            .map_err(|e| format!("h2c handshake failed: {e}"))?;

    tokio::spawn(async move {
        if let Err(err) = conn.await {
            error!("h2c connection failed: {}", err);
        }
    });

    sender
        .send_request(req)
        .await
        .map_err(|e| format!("h2c request failed: {e}"))
}

#[cfg(not(feature = "experimental-h2c"))]
pub async fn forward_h2c_request(
    _req: Request<BoxBody<Bytes, hyper::Error>>,
) -> Result<Response<hyper::body::Incoming>, String> {
    Err("h2c forwarding disabled (build with feature: experimental-h2c)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Empty;

    #[test]
    fn client_header_no_longer_drives_scheme() {
        // R11 regression: a sandboxed worker that sets
        // `x-canister-upstream-scheme: h2c` must NOT cause the proxy to
        // emit h2c upstream. The recipe is the only source of truth.
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/api")
            .header(LEGACY_SCHEME_HEADER, "h2c")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let (_uri, scheme) = build_upstream_uri(&req, "example.com", "http", None).unwrap();
        assert_eq!(scheme, "http", "client header must not influence scheme");
    }

    #[test]
    fn recipe_scheme_overrides_inferred() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/api")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let (_uri, scheme) = build_upstream_uri(&req, "example.com", "http", Some("h2c")).unwrap();
        assert_eq!(scheme, "h2c");
    }

    #[test]
    fn no_recipe_uses_request_uri_scheme() {
        let req = Request::builder()
            .method("GET")
            .uri("https://example.com/api")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let (_uri, scheme) = build_upstream_uri(&req, "example.com", "http", None).unwrap();
        assert_eq!(scheme, "https");
    }
}
