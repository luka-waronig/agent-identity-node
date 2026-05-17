use serde_json::json;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let base_url =
        std::env::var("AGENT_NODE_URL").unwrap_or_else(|_| "http://127.0.0.1:8787".to_string());
    let token = std::env::var("AGENT_NODE_TOKEN")?;
    let client = reqwest::Client::new();

    let manifest: serde_json::Value = client
        .get(format!("{base_url}/manifest"))
        .bearer_auth(&token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    println!("{}", serde_json::to_string_pretty(&manifest)?);

    let result: serde_json::Value = client
        .post(format!("{base_url}/execute"))
        .bearer_auth(&token)
        .json(&json!({ "tool_name": "SCAN_VAULT", "payload": "" }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    println!("{}", serde_json::to_string_pretty(&result)?);

    Ok(())
}
