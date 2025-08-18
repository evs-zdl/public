$subnet = "192.168.1."
$range  = 0..127         
$port   = 3389

foreach ($i in $range) {
    $ip = "$subnet$i"
    if ((Test-NetConnection -ComputerName $ip -Port $port -WarningAction SilentlyContinue).TcpTestSucceeded) {
        Write-Output "$ip : RDP OPEN"
    }
}