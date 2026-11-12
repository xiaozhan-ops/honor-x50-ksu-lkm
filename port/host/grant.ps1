<#
.SYNOPSIS
    Grant or revoke per-app root on this port.

.DESCRIPTION
    Authorisation lives in /data/adb/ksu/.allowlist, read by the kernel module
    at init. Because the module cannot be unloaded while apps hold its driver
    fd, a change only takes effect after a reboot + restore.

    The Manager UI's Superuser tab is not available on this port (the app
    considers the kernel too old), so this script is the supported path.

.EXAMPLE
    .\grant.ps1 -Package com.example.app -Payload E:\payload -Generator .\gen-allowlist.exe

.EXAMPLE
    .\grant.ps1 -Uid 2000 -Payload E:\payload -Generator .\gen-allowlist.exe -NoReboot

.EXAMPLE
    .\grant.ps1 -Package com.example.app -Payload E:\payload -Generator .\gen-allowlist.exe -Remove
#>
[CmdletBinding()]
param(
    [string]$Serial = $env:ADB_SERIAL,
    [string]$Package,
    [string]$Uid,
    [Parameter(Mandatory = $true)][string]$Payload,
    [Parameter(Mandatory = $true)][string]$Generator,
    [switch]$Remove,
    [switch]$NoReboot
)

$ErrorActionPreference = 'Continue'
$adb = if ($env:ADB) { $env:ADB } else { 'adb' }
$target = if ($Serial) { @('-s', $Serial) } else { @() }

function Invoke-Adb([string[]]$a) { & $adb @target @a 2>&1 }
$listPath = Join-Path $Payload 'allowed_uids.txt'

if (-not (Test-Path $Generator)) { Write-Host "[!] generator not found: $Generator" -ForegroundColor Yellow; exit 1 }
if (-not (Test-Path $listPath)) { Set-Content -Path $listPath -Value '2000' -NoNewline }

$t = $null
if ($Uid) {
    $t = $Uid
    Write-Host "[*] raw uid $t"
} elseif ($Package) {
    $line = ((Invoke-Adb @('shell', "pm list packages -U | grep 'package:$Package '")) -join '').Trim()
    if ($line -notmatch 'uid:(\d+)') { Write-Host "[!] cannot resolve uid for $Package" -ForegroundColor Yellow; exit 1 }
    $t = $Matches[1]
    Write-Host "[*] $Package -> uid $t"
} else {
    Write-Host '[!] give -Package <name> or -Uid <uid>'
    exit 1
}

$uids = @((Get-Content $listPath -Raw) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' })

if ($Remove) {
    $uids = $uids | Where-Object { $_ -ne $t }
    Write-Host '[*] revoking'
} else {
    if ($uids -notcontains $t) { $uids += $t }
    Write-Host '[*] granting'
}

$uids = $uids | Select-Object -Unique | Sort-Object
if ($uids.Count -eq 0) { Write-Host '[!] allowlist would be empty; refusing'; exit 1 }

Set-Content -Path $listPath -Value ($uids -join ',') -NoNewline
Write-Host "[*] allowlist uids: $($uids -join ',')"

$out = Join-Path $Payload 'allowlist.bin'
& $Generator $out ($uids -join ',') | Out-Null
Invoke-Adb @('push', $out, '/data/local/tmp/allowlist.bin') | Out-Null
Write-Host ((Invoke-Adb @('shell', 'mkdir -p /data/adb/ksu; cp /data/local/tmp/allowlist.bin /data/adb/ksu/.allowlist; chmod 600 /data/adb/ksu/.allowlist; ls -l /data/adb/ksu/.allowlist')) -join "`n")

if ($NoReboot) {
    Write-Host ''
    Write-Host '[+] allowlist updated (takes effect the next time the module loads)' -ForegroundColor Green
    exit 0
}

Write-Host '[*] applying: reboot + restore...'
& (Join-Path $PSScriptRoot 'restore.ps1') -Payload $Payload -Serial $Serial
