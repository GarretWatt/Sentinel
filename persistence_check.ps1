<#
.SYNOPSIS
  Read-only inspection of common Windows persistence locations.
.DESCRIPTION
  Lists Run keys, Startup folders, scheduled tasks and non-standard services,
  flags entries matching iocs.json, and writes persistence.json for Sentinel.
  Changes nothing on the system and executes nothing it finds.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\persistence_check.ps1
#>
param(
    [string]$IocFile = "$PSScriptRoot\iocs.json",
    [string]$OutFile = "$PSScriptRoot\persistence.json"
)
$ErrorActionPreference = 'SilentlyContinue'

$iocs = (Get-Content $IocFile -Raw | ConvertFrom-Json).indicators
$items = New-Object System.Collections.Generic.List[object]

function Add-Item($Location, $Name, $Value) {
    $text = "$Name $Value"
    $matched = @($iocs | Where-Object {
        $pat = if ($_.regex) { $_.pattern } else { [regex]::Escape($_.pattern) }
        $text -match "(?i)$pat"
    } | ForEach-Object { $_.name })
    $flag = if ($matched.Count -gt 0) { 'ioc' }
            elseif ($Value -match '(?i)\\(AppData|Temp)\\') { 'review' }
            else { '' }
    $items.Add([pscustomobject]@{
        location = $Location; name = [string]$Name
        value = ([string]$Value).Substring(0, [Math]::Min(300, ([string]$Value).Length))
        matched = $matched; flag = $flag
    })
}

# 1. Registry Run keys
$runKeys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($k in $runKeys) {
    $p = Get-ItemProperty $k
    if ($p) {
        $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
            ForEach-Object { Add-Item "Registry: $k" $_.Name $_.Value }
    }
}

# 2. Startup folders
$startup = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
             "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
foreach ($d in $startup) {
    Get-ChildItem $d -File | ForEach-Object { Add-Item "Startup folder: $d" $_.Name $_.FullName }
}

# 3. Scheduled tasks (non-Microsoft)
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
    $act = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
    Add-Item "Scheduled task: $($_.TaskPath)" $_.TaskName $act
}

# 4. Services running outside Windows / Program Files
Get-CimInstance Win32_Service | Where-Object {
    $_.PathName -and $_.PathName -notmatch '(?i)^"?C:\\(Windows|Program Files)'
} | ForEach-Object { Add-Item "Service ($($_.StartMode))" $_.Name $_.PathName }

$result = [ordered]@{
    generated = (Get-Date).ToString('s')
    host      = $env:COMPUTERNAME
    items     = @($items)
}
$result | ConvertTo-Json -Depth 4 | Set-Content -Path $OutFile -Encoding UTF8

$hits = @($items | Where-Object { $_.flag -eq 'ioc' }).Count
$rev  = @($items | Where-Object { $_.flag -eq 'review' }).Count
Write-Host "Checked $($items.Count) entries: $hits IOC match(es), $rev to review."
Write-Host "Wrote $OutFile"
