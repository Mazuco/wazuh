# collect_firefox_history.ps1 - versão simplificada p/ 1 perfil Firefox
$SqliteExe = 'C:\Program Files (x86)\ossec-agent\tools\sqlite3.exe'

# ajuste o nome de usuário:
$user = "$env:USERNAME"
$Places = "C:\Users\$user\AppData\Roaming\Mozilla\Firefox\Profiles\vmrb3t7d.default-release-1754405046938\places.sqlite"

$LogDir = 'C:\Program Files (x86)\ossec-agent\browser_history\logs'
$StateDir = 'C:\Program Files (x86)\ossec-agent\browser_history\state'
New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
New-Item -Path $StateDir -ItemType Directory -Force | Out-Null

$ProfileTag = "${user}_Firefox_vmrb3t7d"
$TempDb = Join-Path $env:TEMP ("places_{0}.db" -f $ProfileTag)
$LogFile = Join-Path $LogDir ("firefox_history_{0}.json" -f $ProfileTag)
$StateFile = Join-Path $StateDir ("firefox_{0}.state" -f $ProfileTag)

if (Test-Path $StateFile) {
    $LAST_PROCESSED = Get-Content $StateFile -Raw
    if (-not ($LAST_PROCESSED -match '^\d+$')) { $LAST_PROCESSED = 0 }
} else {
    # default: últimos 24h
    $unix24 = [int64]((Get-Date).ToUniversalTime().Subtract([datetime]'1970-01-01').TotalSeconds - 86400)
    $LAST_PROCESSED = [int64]($unix24 * 1000000)
}

try {
    Copy-Item -Path $Places -Destination $TempDb -Force -ErrorAction Stop
} catch {
    Write-Host "Falha ao copiar $Places (arquivo bloqueado?)"
    exit 1
}

$query = "SELECT moz_historyvisits.visit_date, datetime(moz_historyvisits.visit_date/1000000, 'unixepoch') AS ts, moz_places.url, moz_places.title FROM moz_historyvisits JOIN moz_places ON moz_historyvisits.place_id = moz_places.id WHERE moz_historyvisits.visit_date > $LAST_PROCESSED ORDER BY moz_historyvisits.visit_date ASC;"
$rows = & $SqliteExe -separator '|' $TempDb $query 2>$null

foreach ($r in $rows) {
    if ([string]::IsNullOrWhiteSpace($r)) { continue }
    $cols = $r -split '\|'
    if ($cols.Count -lt 3) { continue }
    $entry = @{
        browser   = 'Firefox'
        user      = $user
        profile   = 'vmrb3t7d.default-release-1754405046938'
        last_visit_time_raw = $cols[0]
        timestamp = $cols[1]
        url       = $cols[2]
        title     = if ($cols.Count -ge 4) { $cols[3] } else { '' }
        collected_at = (Get-Date).ToString("o")
    }
    $json = ($entry | ConvertTo-Json -Depth 4)
    $json = $json -replace "(`r|`n)"," "
    # Cria um arquivo temporário
    $TempFile = "$LogFile.tmp"

    # Adiciona o JSON ao arquivo temporário de forma segura
    Add-Content -Path $TempFile -Value $json

    # Move/renomeia para o arquivo final de forma atômica
    Move-Item -Path $TempFile -Destination $LogFile -Force
    $LAST_PROCESSED = $cols[0]
}

Set-Content -Path $StateFile -Value $LAST_PROCESSED
Remove-Item -Path $TempDb -Force -ErrorAction SilentlyContinue

