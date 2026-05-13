use bytes::Bytes;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use tracing::debug;

use http_body_util::{BodyExt, Full, combinators::BoxBody};

pub fn is_websocket_upgrade(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

pub async fn not_implemented_ws_bridge() -> Response<BoxBody<Bytes, hyper::Error>> {
    debug!("websocket bridge path selected but not implemented yet");
    let mut resp = Response::new(
        Full::new(Bytes::from_static(b"WebSocket bridge not implemented yet"))
            .map_err(|never| match never {})
            .boxed(),
    );
    *resp.status_mut() = StatusCode::NOT_IMPLEMENTED;
    resp
}
