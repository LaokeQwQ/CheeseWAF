$root = Split-Path -Parent $PSScriptRoot
$packages = @{
    "internal/proxy" = "proxy"
    "internal/engine/decoder" = "decoder"
    "internal/engine/semantic" = "semantic"
    "internal/engine/rules" = "rules"
    "internal/engine/response" = "response"
    "internal/protection/ip" = "ip"
    "internal/protection/ratelimit" = "ratelimit"
    "internal/protection/acl" = "acl"
    "internal/protection/bot" = "bot"
    "internal/protection/tamper" = "tamper"
    "internal/protection/crypto" = "crypto"
    "internal/protection/webshell" = "webshell"
    "internal/storage/log_sink" = "log_sink"
    "internal/api/handler" = "handler"
    "internal/api/middleware" = "middleware"
    "internal/api/dto" = "dto"
    "internal/monitor" = "monitor"
    "internal/monitor/notifier" = "notifier"
    "internal/apisec" = "apisec"
    "internal/edge" = "edge"
    "internal/setup" = "setup"
    "internal/scheduler" = "scheduler"
    "internal/blockpage" = "blockpage"
    "internal/traffic" = "traffic"
    "internal/cli/tui" = "tui"
}

foreach ($entry in $packages.GetEnumerator()) {
    $dir = Join-Path $root $entry.Key
    $file = Join-Path $dir "doc.go"
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    if (!(Test-Path $file)) {
        $content = "// Package $($entry.Value) provides $($entry.Value) functionality for CheeseWAF.`npackage $($entry.Value)`n"
        Set-Content -Path $file -Value $content -Encoding UTF8
    }
}

# Non-Go directories
@("configs/rules", "scripts", "deploy/docker", "deploy/systemd", "docs") | ForEach-Object {
    $dir = Join-Path $root $_
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

Write-Host "Created all package directories successfully."
