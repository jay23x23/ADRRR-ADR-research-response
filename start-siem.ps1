$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

# Restart only an existing Python process already serving EDRRR on its fixed port.
$listeners = @(Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue)
foreach ($listener in $listeners) {
    $existing = Get-CimInstance Win32_Process -Filter "ProcessId=$($listener.OwningProcess)" -ErrorAction SilentlyContinue
    if ($existing -and $existing.Name -match '^python(?:w)?\.exe$' -and $existing.CommandLine -like '*siem_app.py*') {
        Write-Host "Restarting the existing EDRRR process $($existing.ProcessId)..."
        Stop-Process -Id $existing.ProcessId -Force
    } else {
        throw 'Port 8765 is already used by another application. EDRRR did not stop that process.'
    }
}

python siem_app.py
