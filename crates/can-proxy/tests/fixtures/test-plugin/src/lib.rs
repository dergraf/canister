use extism_pdk::*;
use serde_json::json;

#[plugin_fn]
pub fn handle_request(input: String) -> FnResult<String> {
    // Parse the incoming JSON request
    let _req: serde_json::Value = serde_json::from_str(&input)?;

    // Create a mock response
    let resp = json!({
        "status": 200,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": "eyJtZXNzYWdlIjogImhlbGxvIGZyb20gd2FzbSJ9" // {"message": "hello from wasm"} base64 encoded
    });

    Ok(resp.to_string())
}
