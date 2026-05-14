use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;

pub type HttpsClient = Client<HttpsConnector<HttpConnector>, BoxBody<Bytes, hyper::Error>>;

pub fn build_client() -> HttpsClient {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        // SAFETY-UNWRAP: TLS without a trust store is a fatal proxy config;
        // we want a hard, clearly-named startup failure here rather than
        // surfacing it as a per-request error.
        .with_native_roots()
        .expect("no native roots found")
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();

    Client::builder(hyper_util::rt::TokioExecutor::new()).build(https)
}
