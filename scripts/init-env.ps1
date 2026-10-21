# Creates .env from .env.example (if .env does not exist yet) and fills every empty *_PASSWORD
# with a random 24-character alphanumeric value. Passwords are never printed.
# Usage: powershell -ExecutionPolicy Bypass -File scripts\init-env.ps1

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$example = Join-Path $root '.env.example'
$envFile = Join-Path $root '.env'

function New-RandomAlnum([int]$length) {
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'.ToCharArray()
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $limit = 256 - (256 % $chars.Length)   # rejection sampling: avoids modulo bias
    $buf = New-Object byte[] 1
    $sb = New-Object System.Text.StringBuilder
    while ($sb.Length -lt $length) {
        $rng.GetBytes($buf)
        if ($buf[0] -lt $limit) { [void]$sb.Append($chars[$buf[0] % $chars.Length]) }
    }
    $sb.ToString()
}

if (-not (Test-Path $envFile)) {
    Copy-Item $example $envFile
    Write-Host "Created .env from .env.example"
}

# Append variables that exist in .env.example but not yet in .env (keeps existing values untouched)
$existing = @{}
foreach ($l in Get-Content $envFile) { if ($l -match '^([A-Z_]+)=') { $existing[$Matches[1]] = $true } }
$added = 0
foreach ($l in Get-Content $example) {
    if ($l -match '^([A-Z_]+)=' -and -not $existing.ContainsKey($Matches[1])) {
        Add-Content -Path $envFile -Value $l -Encoding UTF8
        $added++
    }
}
if ($added) { Write-Host "Added $added new variable(s) from .env.example" }

$lines = Get-Content $envFile
$filled = 0
$out = foreach ($line in $lines) {
    if ($line -match '^([A-Z_]+_PASSWORD)=\s*$') {
        $filled++
        "$($Matches[1])=$(New-RandomAlnum 24)"
    } else {
        $line
    }
}
# UTF-8 without BOM and LF endings so docker compose reads it cleanly
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($envFile, (($out -join "`n") + "`n"), $utf8NoBom)
Write-Host "Filled $filled empty password variable(s). Values are not shown."
