use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::header::{HOST, TE, TRANSFER_ENCODING};
use hyper::{Request, Response};
#[cfg(feature = "experimental-h2c")]
use hyper_util::rt::TokioIo;
#[cfg(feature = "experimental-h2c")]
use tracing::error;

use crate::client::HttpsClient;

pub fn build_upstream_uri(
    req: &Request<hyper::body::Incoming>,
    host: &str,
    default_scheme: &'static str,
) -> Result<(hyper::Uri, String), String> {
    let original_scheme = req
        .headers()
        .get("x-canister-upstream-scheme")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_else(|| req.uri().scheme_str().unwrap_or(default_scheme))
        .to_string();

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
        req.uri().scheme_str().unwrap_or(default_scheme)
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

pub async fn forward_request(
    client: HttpsClient,
    req: Request<BoxBody<Bytes, hyper::Error>>,
    original_scheme: &str,
) -> Result<Response<hyper::body::Incoming>, String> {
    if original_scheme == "h2c" {
        forward_h2c_request(req).await
    } else {
        client.request(req).await.map_err(|e| e.to_string())
    }
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
