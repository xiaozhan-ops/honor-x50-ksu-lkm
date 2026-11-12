<#
.SYNOPSIS
    One-command recovery: reboot, run the exploit, load kernelsu.ko.

.DESCRIPTION
    Root here is a cred swap performed in RAM: nothing survives a reboot. After
    every reboot this script has to run again, and it has to start within about
    a minute of boot (the exploit's page-oracle only finds a usable physical
    alias during the early boot allocation pattern).

    It is idempotent: if the module is already loaded it exits immediately.

.EXAMPLE
    .\restore.ps1 -Payload E:\payload

.EXAMPLE
    .\restore.ps1 -Serial APLM6R3C20002788 -Payload E:\payload -AllowShell
#>
[CmdletBinding()]
param(
    [string]$Serial = $env:ADB_SERIAL,
    [Parameter(Mandatory = $true)][string]$Payload,
    [switch]$NoReboot,
    [switch]$AllowShell,
    [int]$Attempts = 3
)

$ErrorActionPreference = 'Continue'
$adb = if ($env:ADB) { $env:ADB } else { 'adb' }
$target = if ($Serial) { @('-s', $Serial) } else { @() }

function Say($m)  { Write-Host "[*] $m" }
function Bad($m)  { Write-Host "[!] $m" -ForegroundColor Yellow }
function Good($m) { Write-Host "[+] $m" -ForegroundColor Green }

function Invoke-Adb([string[]]$args2) { & $adb @target @args2 2>&1 }
function Invoke-AdbShell([string]$cmd) { (Invoke-Adb @('shell', $cmd)) -join "`n" }

$files = @('gl_root', 'ksu_ctrl.ko', 'ksud', 'ksu_loader.sh')
foreach ($f in $files) {
    if (-not (Test-Path (Join-Path $Payload $f))) {
        Bad "missing payload file: $f (expected in $Payload)"
        exit 1
    }
}

function Wait-Device([int]$seconds = 90) {
    for ($i = 0; $i -lt $seconds; $i += 2) {
        if ((Invoke-Adb @('devices')) -match '\sdevice$') { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

function ModuleUp {
    return ((Invoke-AdbShell 'ls /sys/module/kernelsu >/dev/null 2>&1 && echo YES || echo NO').Trim() -eq 'YES')
}

function Push-Payload {
    foreach ($f in $files) {
        Invoke-Adb @('push', (Join-Path $Payload $f), "/data/local/tmp/$f") | Out-Null
    }
    $allow = if ($AllowShell) { '1' } else { '0' }
    Invoke-AdbShell "chmod 755 /data/local/tmp/gl_root /data/local/tmp/ksu_loader.sh /data/local/tmp/ksud; " +
                    "chmod 644 /data/local/tmp/ksu_ctrl.ko; " +
                    "sed -i 's/ALLOW_SHELL:-0/ALLOW_SHELL:-$allow/' /data/local/tmp/ksu_loader.sh 2>/dev/null; " +
                    "rm -f /data/local/tmp/ksu_port.log /data/local/tmp/gl_root_proof" | Out-Null
}

Invoke-Adb @('start-server') | Out-Null

if (ModuleUp) {
    Good 'kernelsu.ko already loaded; nothing to do'
    exit 0
}

for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
    Say "===== attempt $attempt/$Attempts ====="

    if ($attempt -gt 1 -or -not $NoReboot) {
        Say 'rebooting (the exploit only works within ~1 minute of boot)'
        Invoke-Adb @('reboot') | Out-Null
        Start-Sleep -Seconds 20
        if (-not (Wait-Device 90)) { Bad 'device did not come back'; continue }
    }

    Say 'pushing payload (fresh copies: hard resets corrupt files on /data)'
    Push-Payload

    Say 'launching exploit'
    Invoke-AdbShell 'cd /data/local/tmp; nohup env SYSCTL_WALK_ATTEMPTS=20 KSU_LOADER=1 KSU_RUNDIR=/data/local/tmp ./gl_root > gl_run.log 2>&1 & echo started' | Out-Null

    Say 'waiting for root + module load (max 150s)'
    $ready = $false
    $why = ''
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 5
        if (ModuleUp) { $ready = $true; break }
        $log = Invoke-AdbShell 'cat /data/local/tmp/ksu_port.log 2>/dev/null'
        if ($log -match 'insmod rc=1') { $why = 'insmod failed (.ko corrupt on device)'; break }
        $run = Invoke-AdbShell 'tail -1 /data/local/tmp/gl_run.log 2>/dev/null'
        if ($run -match 'no usable mapping') { $why = 'dm page search failed (device up too long)'; break }
        if ($run -match 'Exec format error') { $why = 'gl_root corrupt on device'; break }
    }

    if ($ready) {
        Start-Sleep -Seconds 10
        $su = (Invoke-AdbShell '/data/local/tmp/kbin/su -c "id -u"').Trim()
        Good 'kernelsu.ko loaded'
        Write-Host "    shell su -> $su"
        Write-Host ''
        Write-Host '    use: adb shell /data/local/tmp/kbin/su -c "command"' -ForegroundColor Green
        exit 0
    }

    if ($why) { Bad $why } else { Bad 'not ready this round' }
}

Bad 'all attempts failed'
Write-Host '    inspect: adb shell "tail -20 /data/local/tmp/gl_run.log"'
exit 1
