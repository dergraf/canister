use base64::Engine;
use extism_pdk::*;
use serde_json::json;

fn decode_body(payload: &serde_json::Value) -> Vec<u8> {
    let body = payload.get("body").and_then(|b| b.as_str()).unwrap_or("");
    base64::prelude::BASE64_STANDARD
        .decode(body)
        .unwrap_or_default()
}

fn read_header(payload: &serde_json::Value, name: &str) -> Option<String> {
    let headers = payload.get("headers")?.as_object()?;

    if let Some(v) = headers.get(name).and_then(|v| v.as_str()) {
        return Some(v.to_string());
    }

    let lower = name.to_ascii_lowercase();
    headers
        .iter()
        .find_map(|(k, v)| {
            (k.to_ascii_lowercase() == lower)
                .then(|| v.as_str())
                .flatten()
        })
        .map(str::to_string)
}

#[plugin_fn]
pub fn on_request_headers(input: String) -> FnResult<String> {
    let req: serde_json::Value = serde_json::from_str(&input)?;
    let buffer_body = read_header(&req, "x-canister-buffer")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mode = read_header(&req, "x-canister-mode").unwrap_or_default();

    let mut set_headers = serde_json::Map::new();
    set_headers.insert("x-canister-test".to_string(), json!("request-seen"));
    if mode == "inject-remove" {
        set_headers.insert("x-added-by-proxy".to_string(), json!("yes"));
    }

    let remove_headers = if mode == "inject-remove" {
        vec!["x-remove-me"]
    } else {
        Vec::new()
    };

    let resp = json!({
        "action": "Continue",
        "buffer_body": buffer_body,
        "mutations": {
            "set_headers": set_headers,
            "remove_headers": remove_headers
        },
    });

    Ok(resp.to_string())
}

#[plugin_fn]
pub fn on_request_body(input: String) -> FnResult<String> {
    let req: serde_json::Value = serde_json::from_str(&input)?;
    let body = decode_body(&req);
    let end_of_stream = req
        .get("end_of_stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut body = String::from_utf8_lossy(&body).to_uppercase().to_string();
    if !body.is_empty() {
        body.push_str("|RQCHUNK");
    }
    if end_of_stream {
        body.push_str("|REQ-EOS");
    }
    let body = base64::prelude::BASE64_STANDARD.encode(body.as_bytes());

    let resp = json!({
        "action": "Continue",
        "body": body,
    });

    Ok(resp.to_string())
}

#[plugin_fn]
pub fn on_response_headers(input: String) -> FnResult<String> {
    let resp_headers: serde_json::Value = serde_json::from_str(&input)?;
    let buffer_body = read_header(&resp_headers, "x-canister-buffer")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let resp = json!({
        "action": "Continue",
        "buffer_body": buffer_body,
        "mutations": {
            "set_headers": {
                "x-canister-test": "response-seen"
            }
        }
    });

    Ok(resp.to_string())
}

#[plugin_fn]
pub fn on_response_body(input: String) -> FnResult<String> {
    let req: serde_json::Value = serde_json::from_str(&input)?;
    let body = decode_body(&req);
    let end_of_stream = req
        .get("end_of_stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mut text = String::from_utf8_lossy(&body).to_string();
    if !text.is_empty() {
        text.push_str("|RSCHUNK");
    }
    if end_of_stream {
        text.push_str("|RESP-EOS");
    }
    let body = base64::prelude::BASE64_STANDARD.encode(text.as_bytes());

    let resp = json!({
        "action": "Continue",
        "body": body,
    });

    Ok(resp.to_string())
}

#[plugin_fn]
pub fn on_request_trailers(input: String) -> FnResult<String> {
    let _req: serde_json::Value = serde_json::from_str(&input)?;

    let resp = json!({
        "action": "Continue",
        "mutations": {
            "set_headers": {
                "x-original-trailer": "seen"
            }
        }
    });

    Ok(resp.to_string())
}

#[plugin_fn]
pub fn on_response_trailers(input: String) -> FnResult<String> {
    let _req: serde_json::Value = serde_json::from_str(&input)?;

    let resp = json!({
        "action": "Continue",
        "mutations": {
            "set_headers": {
                "x-upstream-trailer": "seen"
            }
        }
    });

    Ok(resp.to_string())
}
