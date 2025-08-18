function Test-TcpPort {
    param(
        [string]$ComputerName,
        [int]$Port = 3389,
        [int]$Timeout = 500   # ms
    )
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        $success = $iar.AsyncWaitHandle.WaitOne($Timeout, $false)
        if ($success -and $client.Connected) {
            $client.EndConnect($iar) | Out-Null
            $client.Close()
            return $true
        }
    } catch { }
    return $false
}

$subnet = "192.168.1."
$range  = 0..127
foreach ($i in $range) {
    $ip = "$subnet$i"
    if (Test-TcpPort -ComputerName $ip -Port 3389 -Timeout 300) {
        Write-Host "$ip : OPEN" -ForegroundColor Green
    }
}
