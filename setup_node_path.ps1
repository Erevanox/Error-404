$src = Join-Path $env:USERPROFILE ".local\node"
$dst = "C:\antigravity\node"

if (-not (Test-Path $dst)) {
    Copy-Item -Path $src -Destination $dst -Recurse -Force
}

$env:PATH = "C:\antigravity\node;$env:USERPROFILE\.local\bin;$env:PATH"
& "C:\antigravity\node\node.exe" --version
& "C:\antigravity\node\npm.cmd" --version
