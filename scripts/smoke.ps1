param(
  [int]$Port = 18787,
  [string]$Profile = ".smoke-node"
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $root

$env:AIN_IDENTITY_PASSWORD = "agent-identity-node-smoke-test"

function Assert-SafeSmokePath {
  param([string]$PathValue)

  if ([string]::IsNullOrWhiteSpace($PathValue)) {
    throw "smoke profile path must not be empty"
  }
  if ([System.IO.Path]::IsPathRooted($PathValue)) {
    throw "smoke profile path must be relative to the repository"
  }

  $fullPath = [System.IO.Path]::GetFullPath((Join-Path $root $PathValue))
  if (-not $fullPath.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "smoke profile path must stay inside the repository"
  }

  return $fullPath
}

$profilePath = Assert-SafeSmokePath $Profile

if (Test-Path $profilePath) {
  Remove-Item -LiteralPath $profilePath -Recurse -Force
}

cargo run -p agent-node-daemon -- init --profile $Profile --role researcher-agent | Out-Host

$job = Start-Job -ScriptBlock {
  param($Root, $Profile, $Port)
  Set-Location $Root
  $env:AIN_IDENTITY_PASSWORD = "agent-identity-node-smoke-test"
  cargo run -p agent-node-daemon -- run --profile $Profile --port $Port
} -ArgumentList $root, $Profile, $Port

try {
  $base = "http://127.0.0.1:$Port"
  $ready = $false
  for ($i = 0; $i -lt 60; $i++) {
    try {
      Invoke-RestMethod "$base/healthz" | Out-Null
      $ready = $true
      break
    } catch {
      Start-Sleep -Seconds 1
    }
  }
  if (-not $ready) {
    throw "agent-node daemon did not become ready on $base"
  }

  $token = Get-Content (Join-Path $Profile "agent.token")
  $agentCard = Invoke-RestMethod "$base/.well-known/agent-card.json"
  $mcpInitBody = @{
    jsonrpc = "2.0"
    id = 1
    method = "initialize"
  } | ConvertTo-Json
  Invoke-RestMethod "$base/mcp" `
    -Method Post `
    -ContentType "application/json" `
    -Body $mcpInitBody | Out-Null

  $authRequest = Invoke-RestMethod "$base/auth/request-code" `
    -Method Post `
    -ContentType "application/json" `
    -Body '{"subject":"smoke-agent","requested_scopes":["manifest:read","capabilities:read","tool:scan_vault"]}'

  $grantBody = @{
    request_id = $authRequest.request.request_id
    subject = "smoke-agent"
    scopes = @("manifest:read", "capabilities:read", "tool:scan_vault")
    ttl_seconds = 300
  } | ConvertTo-Json

  $grant = Invoke-RestMethod "$base/auth/grants" `
    -Method Post `
    -ContentType "application/json" `
    -Headers @{ Authorization = "Bearer $token" } `
    -Body $grantBody

  $manifest = Invoke-RestMethod "$base/manifest" `
    -Headers @{ Authorization = $grant.authorization_header }

  $scan = Invoke-RestMethod "$base/execute" `
    -Method Post `
    -ContentType "application/json" `
    -Headers @{ Authorization = $grant.authorization_header } `
    -Body '{"tool_name":"SCAN_VAULT","payload":""}'

  $mcpListBody = @{
    jsonrpc = "2.0"
    id = 2
    method = "tools/list"
  } | ConvertTo-Json
  Invoke-RestMethod "$base/mcp" `
    -Method Post `
    -ContentType "application/json" `
    -Headers @{ Authorization = $grant.authorization_header } `
    -Body $mcpListBody | Out-Null

  $mcpCallBody = @{
    jsonrpc = "2.0"
    id = 3
    method = "tools/call"
    params = @{
      name = "SCAN_VAULT"
      arguments = @{
        payload = ""
      }
    }
  } | ConvertTo-Json -Depth 5
  $mcpCall = Invoke-RestMethod "$base/mcp" `
    -Method Post `
    -ContentType "application/json" `
    -Headers @{ Authorization = $grant.authorization_header } `
    -Body $mcpCallBody

  [pscustomobject]@{
    peer_id = $manifest.peer_id
    agent_card = $agentCard.name
    grant_subject = $grant.grant.claims.subject
    execute_result = $scan.result
    mcp_result = $mcpCall.result.content[0].text
  } | Format-List
}
finally {
  Stop-Job $job -ErrorAction SilentlyContinue
  Remove-Job $job -ErrorAction SilentlyContinue
  if (Test-Path $profilePath) {
    Remove-Item -LiteralPath $profilePath -Recurse -Force
  }
  if (Test-Path "vault_researcher-agent") {
    Remove-Item -LiteralPath "vault_researcher-agent" -Recurse -Force
  }
}
