$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$nodePath = "$env:USERPROFILE\.local\node"
$binPath = "$env:USERPROFILE\.local\bin"

if ($userPath -notlike "*$nodePath*") {
    $userPath = "$nodePath;$userPath"
}
if ($userPath -notlike "*$binPath*") {
    $userPath = "$binPath;$userPath"
}

[Environment]::SetEnvironmentVariable('Path', $userPath, 'User')
Write-Host "Updated User PATH to: $userPath"
