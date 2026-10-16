$env:PATH = "C:\antigravity\node;$env:USERPROFILE\.local\bin;" + $env:PATH
Set-Location "c:\antigravity\trace x\frontend"
& "C:\antigravity\node\node.exe" "C:\antigravity\node\node_modules\npm\bin\npm-cli.js" install --no-audit --no-fund
Write-Host "Exit code: $LASTEXITCODE"
