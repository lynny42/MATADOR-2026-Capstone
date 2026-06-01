# Monitor connections to local port 6000 (when API already listens).
$seen = @{}
Write-Host "=== Watching TCP :6000 (existing listener) ===" -ForegroundColor Cyan
Write-Host "Started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') — Ctrl+C to stop`n"
while ($true) {
    $rows = Get-NetTCPConnection -LocalPort 6000 -ErrorAction SilentlyContinue
    foreach ($r in $rows) {
        $key = "$($r.State)|$($r.RemoteAddress)|$($r.RemotePort)|$($r.OwningProcess)"
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Write-Host "[$ts] $($r.State) remote=$($r.RemoteAddress):$($r.RemotePort) pid=$($r.OwningProcess)"
        }
    }
    Start-Sleep -Milliseconds 500
}
