$nodeDir = Join-Path $env:USERPROFILE ".local\node"
$zipPath = Join-Path $env:USERPROFILE ".local\node.zip"
$localDir = Join-Path $env:USERPROFILE ".local"

if (-not (Test-Path $nodeDir)) {
    New-Item -ItemType Directory -Path $localDir -Force | Out-Null
    Write-Host "Downloading Node.js portable zip..."
    Invoke-WebRequest -Uri "https://nodejs.org/dist/v20.18.0/node-v20.18.0-win-x64.zip" -OutFile $zipPath
    Write-Host "Extracting Node.js zip..."
    Expand-Archive -Path $zipPath -DestinationPath $localDir -Force
    Remove-Item $zipPath -Force
    Rename-Item (Join-Path $localDir "node-v20.18.0-win-x64") "node" -Force
}

$env:PATH = "$nodeDir;$env:USERPROFILE\.local\bin;$env:PATH"
Write-Host "Verifying Node and UV:"
& "$nodeDir\node.exe" --version
& "$nodeDir\npm.cmd" --version
& "$env:USERPROFILE\.local\bin\uv.exe" --version
