# BlockWatch helper script
# Scans the Minecraft server latest.log file directly without copying it.

$MinecraftLog = "$env:USERPROFILE\Desktop\minecraft_test_server\logs\latest.log"
$OutputFolder = "server_log_scan"

Write-Host "Running BlockWatch against Minecraft latest.log..."
Write-Host "Log file: $MinecraftLog"
Write-Host "Output folder: $OutputFolder"

py src/main.py --log "$MinecraftLog" --output "$OutputFolder" --no-ai

Write-Host ""
Write-Host "Scan complete."
Write-Host "Report saved to: $OutputFolder\suspicious_activity_report.txt"
