$bytes = [System.IO.File]::ReadAllBytes('F:\Project\git\appcontainer\opencode.exe')
$nameOffset = 0x7514374
Write-Host "File size: $($bytes.Length) (0x$($bytes.Length.ToString('X')))"
Write-Host "DLL name at offset: 0x7514374"
Write-Host ""

# Search for MZ+PE DLL headers within 16MB before the DLL name
Write-Host "--- Scanning for PE DLL headers near DLL name offset ---"
$searchStart = [Math]::Max(0, $nameOffset - 16 * 1024 * 1024)
$found = 0
for ($i = $searchStart; $i -lt $nameOffset; $i++) {
    if ($bytes[$i] -eq 0x4D -and $bytes[$i+1] -eq 0x5A) {
        if (($i + 0x3C + 4) -lt $bytes.Length) {
            $peOff = [BitConverter]::ToUInt32($bytes, $i + 0x3C)
            if ($peOff -ge 0x40 -and $peOff -le 0x10000 -and ($i + $peOff + 24) -lt $bytes.Length) {
                $sig0 = $bytes[$i + $peOff]
                $sig1 = $bytes[$i + $peOff + 1]
                $sig2 = $bytes[$i + $peOff + 2]
                $sig3 = $bytes[$i + $peOff + 3]
                if ($sig0 -eq 0x50 -and $sig1 -eq 0x45 -and $sig2 -eq 0 -and $sig3 -eq 0) {
                    $chars = [BitConverter]::ToUInt16($bytes, $i + $peOff + 4 + 18)
                    $isDll = ($chars -band 0x2000) -ne 0
                    $machine = [BitConverter]::ToUInt16($bytes, $i + $peOff + 4)
                    $sections = [BitConverter]::ToUInt16($bytes, $i + $peOff + 4 + 2)
                    $mod512 = $i % 512
                    Write-Host "  MZ+PE at 0x$($i.ToString('X8')), machine=0x$($machine.ToString('X4')), chars=0x$($chars.ToString('X4')), isDLL=$isDll, sections=$sections, mod512=$mod512"
                    $found++
                    if ($found -ge 30) { Write-Host "  (stopped at 30)"; break }
                }
            }
        }
    }
}
Write-Host "Found $found PE headers near DLL name"

# Also scan the ENTIRE binary for DLL PE headers (at any alignment)
Write-Host ""
Write-Host "--- Full binary scan for PE DLL headers (any alignment) ---"
$dllFound = 0
for ($i = 0; $i -lt ($bytes.Length - 0x200); $i++) {
    if ($bytes[$i] -eq 0x4D -and $bytes[$i+1] -eq 0x5A) {
        if (($i + 0x3C + 4) -lt $bytes.Length) {
            $peOff = [BitConverter]::ToUInt32($bytes, $i + 0x3C)
            if ($peOff -ge 0x40 -and $peOff -le 0x10000 -and ($i + $peOff + 24) -lt $bytes.Length) {
                $sig0 = $bytes[$i + $peOff]
                $sig1 = $bytes[$i + $peOff + 1]
                $sig2 = $bytes[$i + $peOff + 2]
                $sig3 = $bytes[$i + $peOff + 3]
                if ($sig0 -eq 0x50 -and $sig1 -eq 0x45 -and $sig2 -eq 0 -and $sig3 -eq 0) {
                    $chars = [BitConverter]::ToUInt16($bytes, $i + $peOff + 4 + 18)
                    $isDll = ($chars -band 0x2000) -ne 0
                    if ($isDll) {
                        $machine = [BitConverter]::ToUInt16($bytes, $i + $peOff + 4)
                        $sections = [BitConverter]::ToUInt16($bytes, $i + $peOff + 4 + 2)
                        $optSize = [BitConverter]::ToUInt16($bytes, $i + $peOff + 4 + 16)
                        Write-Host "  DLL at 0x$($i.ToString('X8')), machine=0x$($machine.ToString('X4')), sections=$sections, optHdrSize=$optSize, mod512=$($i % 512)"
                        $dllFound++
                        if ($dllFound -ge 20) { Write-Host "  (stopped at 20)"; break }
                    }
                }
            }
        }
    }
}
Write-Host "Found $dllFound DLL PE headers in entire binary"
