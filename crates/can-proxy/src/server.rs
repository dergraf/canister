use std::sync::Arc;

use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tracing::{debug, error, info};

use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::ca::DynamicCa;
use crate::wasm::WasmEngine;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("CA error: {0}")]
    Ca(#[from] crate::ca::CaError),
    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("Wasm error: {0}")]
    Wasm(#[from] crate::wasm::WasmError),
}

pub struct ProxyServer {
    ca: Arc<DynamicCa>,
    wasm_engine: Arc<WasmEngine>,
}

impl ProxyServer {
    pub fn new(
        ca: DynamicCa,
        interceptors: &std::collections::HashMap<String, std::path::PathBuf>,
    ) -> Result<Self, ProxyError> {
        let wasm_engine = WasmEngine::new(interceptors)?;
        Ok(Self {
            ca: Arc::new(ca),
            wasm_engine: Arc::new(wasm_engine),
        })
    }

    pub fn new_with_arc(
        ca: Arc<DynamicCa>,
        interceptors: &std::collections::HashMap<String, std::path::PathBuf>,
    ) -> Result<Self, ProxyError> {
        let wasm_engine = WasmEngine::new(interceptors)?;
        Ok(Self {
            ca,
            wasm_engine: Arc::new(wasm_engine),
        })
    }

    pub async fn run(&self, listener: tokio::net::TcpListener) -> Result<(), ProxyError> {
        info!("Proxy server listening on {}", listener.local_addr()?);

        loop {
            let (stream, _peer_addr) = listener.accept().await?;
            let io = TokioIo::new(stream);

            let ca = self.ca.clone();
            let wasm_engine = self.wasm_engine.clone();
            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .serve_connection(
                        io,
                        service_fn(move |req| {
                            handle_proxy_request(req, ca.clone(), wasm_engine.clone())
                        }),
                    )
                    .with_upgrades()
                    .await
                {
                    error!("Failed to serve connection: {:?}", err);
                }
            });
        }
    }
}

async fn handle_proxy_request(
    req: Request<hyper::body::Incoming>,
    ca: Arc<DynamicCa>,
    wasm_engine: Arc<WasmEngine>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    if req.method() == Method::CONNECT {
        let authority = req
            .uri()
            .authority()
            .map(|a| a.to_string())
            .unwrap_or_default();
        let host_name_only = authority.split(':').next().unwrap_or("").to_string();
        debug!("Received CONNECT request for {}", authority);

        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    if wasm_engine.has_plugin(&host_name_only) {
                        if let Err(e) =
                            handle_tunnel(upgraded, host_name_only, ca, wasm_engine).await
                        {
                            error!("TLS Tunnel error for {}: {}", authority, e);
                        }
                    } else if let Err(e) = handle_passthrough(upgraded, authority.clone()).await {
                        error!("Passthrough error for {}: {}", authority, e);
                    }
                }
                Err(e) => error!("Upgrade error: {}", e),
            }
        });

        let mut resp = Response::new(empty_body());
        *resp.status_mut() = StatusCode::OK;
        return Ok(resp);
    }

    // For plain HTTP requests
    let host = req.uri().host().map(|s| s.to_string()).unwrap_or_else(|| {
        req.headers()
            .get(hyper::header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h).to_string())
            .unwrap_or_default()
    });
    if wasm_engine.has_plugin(&host) {
        return handle_inner_request(req, wasm_engine).await;
    }

    // Plain HTTP passthrough
    handle_http_passthrough(req).await
}

async fn handle_http_passthrough(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let host = req.uri().host().map(|s| s.to_string()).unwrap_or_else(|| {
        req.headers()
            .get(hyper::header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h).to_string())
            .unwrap_or_default()
    });
    let port = req.uri().port_u16().unwrap_or(80);

    match tokio::net::TcpStream::connect((host.as_str(), port)).await {
        Ok(stream) => {
            let io = TokioIo::new(stream);
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .handshake(io)
                .await?;

            tokio::task::spawn(async move {
                if let Err(err) = conn.await {
                    error!("Connection failed: {:?}", err);
                }
            });

            sender
                .send_request(req)
                .await
                .map(|res| res.map(|body| body.boxed()))
        }
        Err(e) => {
            let mut resp = Response::new(full_body(format!("Bad Gateway: {}", e)));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            Ok(resp)
        }
    }
}

async fn handle_passthrough(upgraded: Upgraded, target: String) -> Result<(), std::io::Error> {
    debug!("Establishing TCP passthrough for {}", target);
    let mut server = tokio::net::TcpStream::connect(&target).await?;
    let mut client = TokioIo::new(upgraded);
    tokio::io::copy_bidirectional(&mut client, &mut server).await?;
    Ok(())
}

async fn handle_inner_request(
    req: Request<hyper::body::Incoming>,
    wasm_engine: Arc<WasmEngine>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    debug!("Intercepting request: {} {}", req.method(), req.uri());

    let host = req.uri().host().map(|s| s.to_string()).unwrap_or_else(|| {
        req.headers()
            .get(hyper::header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h).to_string())
            .unwrap_or_default()
    });

    if wasm_engine.has_plugin(&host) {
        // Read the entire body
        let (parts, body) = req.into_parts();
        let body_bytes = body.collect().await?.to_bytes();

        let req_json = serde_json::json!({
            "method": parts.method.as_str(),
            "uri": parts.uri.to_string(),
            "headers": parts.headers.iter().map(|(k, v)| (k.as_str(), v.to_str().unwrap_or(""))).collect::<std::collections::HashMap<_, _>>(),
            "body": base64::prelude::BASE64_STANDARD.encode(&body_bytes)
        });

        match wasm_engine.execute(
            &host,
            "handle_request",
            serde_json::to_vec(&req_json).unwrap(),
        ) {
            Ok(output) => {
                if let Ok(resp_json) = serde_json::from_slice::<serde_json::Value>(&output) {
                    let mut builder = Response::builder();
                    if let Some(status) = resp_json.get("status").and_then(|s| s.as_u64()) {
                        builder = builder.status(status as u16);
                    }

                    if let Some(headers) = resp_json.get("headers").and_then(|h| h.as_object()) {
                        for (k, v) in headers {
                            if let Some(v_str) = v.as_str() {
                                builder = builder.header(k, v_str);
                            }
                        }
                    }

                    let body_bytes =
                        if let Some(body_b64) = resp_json.get("body").and_then(|b| b.as_str()) {
                            base64::prelude::BASE64_STANDARD
                                .decode(body_b64)
                                .unwrap_or_default()
                        } else {
                            vec![]
                        };

                    let resp = builder.body(full_body(body_bytes)).unwrap_or_else(|_| {
                        let mut resp = Response::new(full_body("Internal Server Error"));
                        *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                        resp
                    });
                    return Ok(resp);
                }
            }
            Err(e) => {
                error!("Wasm execution failed for {}: {}", host, e);
            }
        }
    }

    // Pass through or drop if no Wasm? For now, we drop if intercepted.
    let mut resp = Response::new(full_body(
        "Canister Proxy: Request intercepted but Wasm failed or no plugin found.",
    ));
    *resp.status_mut() = StatusCode::BAD_GATEWAY;
    Ok(resp)
}

async fn handle_tunnel(
    upgraded: Upgraded,
    host_with_port: String,
    ca: Arc<DynamicCa>,
    wasm_engine: Arc<WasmEngine>,
) -> Result<(), std::io::Error> {
    let host = host_with_port.split(':').next().unwrap_or("").to_string();
    debug!("Establishing TLS tunnel for {}", host);

    let (cert, key) = ca.generate_server_cert(&host).map_err(|e| {
        std::io::Error::other(
            format!("Failed to generate cert: {}", e),
        )
    })?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    let io = TokioIo::new(upgraded);
    let tls_stream = tls_acceptor.accept(io).await?;
    let tls_io = TokioIo::new(tls_stream);

    http1::Builder::new()
        .serve_connection(
            tls_io,
            service_fn(move |req| handle_inner_request(req, wasm_engine.clone())),
        )
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    Ok(())
}

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full_body<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}
