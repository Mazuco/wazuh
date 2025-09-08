# collect_firefox_history.ps1
$SqliteExe = 'C:\ProgramData\Wazuh\tools\sqlite3.exe'
$RootUsers = 'C:\Users'
$LogDir = 'C:\ProgramData\Wazuh\browser_history\logs'
$StateDir = 'C:\ProgramData\Wazuh\browser_history\state'
New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
New-Item -Path $StateDir -ItemType Directory -Force | Out-Null

foreach ($user in Get-ChildItem -Path $RootUsers -Directory | Where-Object { $_.Name -notin @('Public','Default') }) {
    $ProfilesBase = Join-Path $user.FullName 'AppData\Roaming\Mozilla\Firefox\Profiles'
    if (-not (Test-Path $ProfilesBase)) { continue }
    # pick all profiles and choose the one with places.sqlite
    foreach ($p in Get-ChildItem -Path $ProfilesBase -Directory) {
        $Places = Join-Path $p.FullName 'places.sqlite'
        if (-not (Test-Path $Places)) { continue }

        $ProfileTag = ($user.Name) + '_Firefox_' + $p.Name
        $TempDb = Join-Path $env:TEMP ("places_{0}.db" -f $ProfileTag)
        $LogFile = Join-Path $LogDir ("firefox_history_{0}.json" -f $ProfileTag)
        $StateFile = Join-Path $StateDir ("firefox_{0}.state" -f $ProfileTag)

        if (Test-Path $StateFile) {
            $LAST_PROCESSED = Get-Content $StateFile -Raw
            if (-not ($LAST_PROCESSED -match '^\d+$')) { $LAST_PROCESSED = 0 }
        } else {
            # default: last 24h -> convert to microseconds since 1970
            $unix24 = [int64]((Get-Date).ToUniversalTime().Subtract([datetime]'1970-01-01').TotalSeconds - 86400)
            $LAST_PROCESSED = [int64]($unix24 * 1000000)
        }

        try {
            Copy-Item -Path $Places -Destination $TempDb -Force -ErrorAction Stop
        } catch {
            Write-Verbose "Copy failed for $Places - consider DiskShadow fallback"
            continue
        }

        $query = "SELECT moz_historyvisits.visit_date, datetime(moz_historyvisits.visit_date/1000000, 'unixepoch') AS ts, moz_places.url, moz_places.title FROM moz_historyvisits JOIN moz_places ON moz_historyvisits.place_id = moz_places.id WHERE moz_historyvisits.visit_date > $LAST_PROCESSED ORDER BY moz_historyvisits.visit_date ASC;"
        $rows = & $SqliteExe -separator '|' $TempDb $query 2>$null

        foreach ($r in $rows) {
            if ([string]::IsNullOrWhiteSpace($r)) { continue }
            $cols = $r -split '\|'
            if ($cols.Count -lt 3) { continue }
            $entry = @{
                browser   = 'Firefox'
                user      = $user.Name
                profile   = $p.Name
                last_visit_time_raw = $cols[0]
                timestamp = $cols[1]
                url       = $cols[2]
                title     = if ($cols.Count -ge 4) { $cols[3] } else { '' }
                collected_at = (Get-Date).ToString("o")
            }
            $json = ($entry | ConvertTo-Json -Depth 4)
            $json = $json -replace "(`r|`n)"," "
            Add-Content -Path $LogFile -Value $json
            $LAST_PROCESSED = $cols[0]
        }

        Set-Content -Path $StateFile -Value $LAST_PROCESSED
        Remove-Item -Path $TempDb -Force -ErrorAction SilentlyContinue
    }
}

