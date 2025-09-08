# collect_chromium_history.ps1
# Requisitos: executar como Administrador, sqlite3.exe disponível (path abaixo)
$SqliteExe = 'C:\Program Files (x86)\ossec-agent\tools\sqlite3.exe'
$RootUsers = 'C:\Users'
$Browsers = @(
  @{Name='Chrome'; Rel='AppData\Local\Google\Chrome\User Data'},
  @{Name='Edge';   Rel='AppData\Local\Microsoft\Edge\User Data'}
)
$LogDir = 'C:\Program Files (x86)\ossec-agent\browser_history\logs'
$StateDir = 'C:\Program Files (x86)\ossec-agent\browser_history\state'
New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
New-Item -Path $StateDir -ItemType Directory -Force | Out-Null

function Copy-WithFallback {
    param($Source, $Dest)
    try {
        Copy-Item -Path $Source -Destination $Dest -Force -ErrorAction Stop
        return $true
    } catch {
        # fallback: signal failure to caller (DiskShadow handled outside)
        return $false
    }
}

foreach ($user in Get-ChildItem -Path $RootUsers -Directory | Where-Object { $_.Name -notin @('Public','Default') }) {
    foreach ($b in $Browsers) {
        $Base = Join-Path $user.FullName $b.Rel
        if (-not (Test-Path $Base)) { continue }
        # iterate profiles (Default, Profile 1, Profile 2 ...)
        foreach ($profile in Get-ChildItem -Path $Base -Directory) {
            $HistoryPath = Join-Path $profile.FullName 'History'
            if (-not (Test-Path $HistoryPath)) { continue }

            $ProfileTag = ($user.Name) + '_' + ($b.Name) + '_' + ($profile.Name)
            $TempDb = Join-Path $env:TEMP ("History_{0}.db" -f $ProfileTag)
            $LogFile = Join-Path $LogDir ("chromium_history_{0}.json" -f $ProfileTag)
            $StateFile = Join-Path $StateDir ("chromium_{0}.state" -f $ProfileTag)

            # get LAST_PROCESSED (stored as Chrome webkit microseconds since 1601)
            if (Test-Path $StateFile) {
                $LAST_PROCESSED = Get-Content $StateFile -Raw
                if (-not ($LAST_PROCESSED -match '^\d+$')) { $LAST_PROCESSED = 0 }
            } else {
                # default: last 24h
                $unix24 = [int64]((Get-Date).ToUniversalTime().Subtract([datetime]'1970-01-01').TotalSeconds - 86400)
                $LAST_PROCESSED = [int64](($unix24 + 11644473600) * 1000000)
            }

            $copied = Copy-WithFallback -Source $HistoryPath -Dest $TempDb
            if (-not $copied) {
                # If failed, skip here and optionally use DiskShadow fallback (see docs in the playbook).
                Write-Verbose "Failed to copy $HistoryPath - consider running DiskShadow fallback"
                continue
            }

            # query sqlite - return pipes: last_visit_time|ts|url|title
            $query = "SELECT last_visit_time, datetime(last_visit_time/1000000 - 11644473600, 'unixepoch') AS ts, url, title FROM urls WHERE last_visit_time > $LAST_PROCESSED ORDER BY last_visit_time ASC;"
            $rows = & $SqliteExe -separator '|' $TempDb $query 2>$null

            foreach ($r in $rows) {
                if ([string]::IsNullOrWhiteSpace($r)) { continue }
                $cols = $r -split '\|'
                if ($cols.Count -lt 3) { continue }
                $entry = @{
                    browser   = $b.Name
                    user      = $user.Name
                    profile   = $profile.Name
                    last_visit_time_raw = $cols[0]
                    timestamp = $cols[1]
                    url       = $cols[2]
                    title     = if ($cols.Count -ge 4) { $cols[3] } else { '' }
                    collected_at = (Get-Date).ToString("o")
                }
                $json = ($entry | ConvertTo-Json -Depth 4)
                $json = $json -replace "(`r|`n)"," "   # single-line JSON
                Add-Content -Path $LogFile -Value $json
                # update LAST_PROCESSED progressively
                $LAST_PROCESSED = $cols[0]
            }

            # persist LAST_PROCESSED
            Set-Content -Path $StateFile -Value $LAST_PROCESSED
            Remove-Item -Path $TempDb -Force -ErrorAction SilentlyContinue
        }
    }
}

