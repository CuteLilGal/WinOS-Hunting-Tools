<#
.SYNOPSIS
    Full binary audit: Hash + Authenticode signature + Version info + Metadata.

.DESCRIPTION
    Enumerates files matching the given extensions under one or more paths
    (optionally recursive) and collects forensic / audit metadata into
    CSV, JSON, or the pipeline. Designed for enterprise DLL/EXE inventory,
    supply-chain auditing, and unsigned-binary hunting.

.PARAMETER Path
    One or more directories to scan. Accepts pipeline input.
    Default: C:\Windows\System32

.PARAMETER Recurse
    Recurse into subdirectories. Alias: -r

.PARAMETER Extension
    File patterns to include. Default: *.dll
    Example: -Extension *.dll,*.exe,*.sys,*.ocx

.PARAMETER OutputPath
    Output file path. If omitted, a timestamped file is written to the
    current directory, e.g. file_audit_20261224_153012.csv

.PARAMETER Format
    Csv | Json | PassThru. Default: Csv

.PARAMETER Algorithm
    Hash algorithm. Default: SHA256

.PARAMETER OnlyUnsigned
    Emit only files with Status NotSigned / HashMismatch / NotTrusted /
    UnknownError. Exits with code 2 if any are found (useful in CI).

.PARAMETER ExcludePath
    Wildcard patterns to skip, e.g. '*\WinSxS\*','*\Temp\*'.

.PARAMETER MaxSizeMB
    Skip files larger than this size in MB. 0 = no limit (default).

.PARAMETER Parallel
    Use ForEach-Object -Parallel. Requires PowerShell 7+.

.PARAMETER ThrottleLimit
    Max concurrent threads when -Parallel is used. Default: 8

.EXAMPLE
    .\Invoke-FileAudit.ps1
    Audit default System32 DLLs to a timestamped CSV.

.EXAMPLE
    .\Invoke-FileAudit.ps1 -Path 'C:\Program Files' -r -Extension *.dll,*.exe -Parallel
    Recursive, parallel audit of DLLs and EXEs under Program Files.

.EXAMPLE
    .\Invoke-FileAudit.ps1 -Path C:\Windows -r -OnlyUnsigned -Format Json
    Hunt every unsigned binary under C:\Windows, emit JSON.

.EXAMPLE
    'C:\Windows\System32','C:\Windows\SysWOW64' | .\Invoke-FileAudit.ps1 -r
    Pipeline multiple paths.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Path = @("C:\Windows\System32"),

    [Alias("r")]
    [switch]$Recurse,

    [ValidateNotNullOrEmpty()]
    [string[]]$Extension = @("*.dll"),

    [string]$OutputPath,

    [ValidateSet("Csv", "Json", "PassThru")]
    [string]$Format = "Csv",

    [ValidateSet("MD5", "SHA1", "SHA256", "SHA384", "SHA512")]
    [string]$Algorithm = "SHA256",

    [switch]$OnlyUnsigned,

    [string[]]$ExcludePath,

    [ValidateRange(0, [int]::MaxValue)]
    [int]$MaxSizeMB = 0,

    [switch]$Parallel,

    [ValidateRange(1, 64)]
    [int]$ThrottleLimit = 8
)

begin {
    $script:startTime = Get-Date
    $script:results   = [System.Collections.Generic.List[object]]::new()
    $script:errors    = [System.Collections.Generic.List[string]]::new()

    # --- Elevation check -----------------------------------------------------
    $currentId = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$currentId
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "Not running elevated. Some system files may be inaccessible."
    }

    # --- Resolve output paths ------------------------------------------------
    if (-not $OutputPath) {
        $stamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
        $ext        = if ($Format -eq 'Json') { '.json' } else { '.csv' }
        $OutputPath = Join-Path (Get-Location) "file_audit_$stamp$ext"
    }
    $ErrorLogPath = [IO.Path]::ChangeExtension($OutputPath, '.errors.log')

    # --- Parallel guard ------------------------------------------------------
    if ($Parallel -and $PSVersionTable.PSVersion.Major -lt 7) {
        Write-Warning "-Parallel requires PowerShell 7+. Falling back to sequential."
        $Parallel = $false
    }

    # --- Single processing block (reused sequential and parallel) -----------
    $script:processBlock = {
        param($file, $Alg)
        try {
            $hash = Get-FileHash $file.FullName -Algorithm $Alg -ErrorAction Stop
            $sig  = Get-AuthenticodeSignature $file.FullName -ErrorAction SilentlyContinue
            $ver  = $file.VersionInfo
            $cert = $sig.SignerCertificate

            [PSCustomObject]@{
                Path             = $file.FullName
                FileName         = $file.Name
                Extension        = $file.Extension
                Directory        = $file.DirectoryName
                Size             = $file.Length
                CreationTime     = $file.CreationTime
                LastAccessTime   = $file.LastAccessTime
                LastWriteTime    = $file.LastWriteTime
                HashAlgorithm    = $Alg
                Hash             = $hash.Hash
                SigStatus        = $sig.Status
                StatusMessage    = $sig.StatusMessage
                Signer           = if ($cert) { $cert.Subject }      else { "N/A" }
                Issuer           = if ($cert) { $cert.Issuer }       else { "N/A" }
                SerialNumber     = if ($cert) { $cert.SerialNumber } else { "N/A" }
                Thumbprint       = if ($cert) { $cert.Thumbprint }   else { "N/A" }
                NotBefore        = if ($cert) { $cert.NotBefore }    else { "N/A" }
                NotAfter         = if ($cert) { $cert.NotAfter }     else { "N/A" }
                FileVersion      = $ver.FileVersion
                ProductVersion   = $ver.ProductVersion
                FileDescription  = $ver.FileDescription
                ProductName      = $ver.ProductName
                CompanyName      = $ver.CompanyName
                OriginalFilename = $ver.OriginalFilename
                InternalName     = $ver.InternalName
                LegalCopyright   = $ver.LegalCopyright
                IsReadOnly       = $file.IsReadOnly
                Attributes       = $file.Attributes
                Error            = $null
            }
        }
        catch {
            [PSCustomObject]@{
                Path  = $file.FullName
                Error = $_.Exception.Message
            }
        }
    }
}

process {
    foreach ($p in $Path) {
        if (-not (Test-Path -LiteralPath $p)) {
            $script:errors.Add("Path not found: $p")
            Write-Error "Path not found: $p"
            continue
        }

        Write-Host "[+] Scanning $p  (Recurse=$Recurse, Parallel=$Parallel, Algo=$Algorithm)" -ForegroundColor Cyan

        # Enumerate -- use -Filter (provider-level, fast) when single extension
        $files = if ($Extension.Count -eq 1) {
            Get-ChildItem -Path $p -Filter $Extension[0] -File -Recurse:$Recurse -ErrorAction SilentlyContinue
        }
        else {
            Get-ChildItem -Path $p -File -Recurse:$Recurse -ErrorAction SilentlyContinue |
                Where-Object {
                    $n = $_.Name
                    foreach ($pat in $Extension) { if ($n -like $pat) { return $true } }
                    return $false
                }
        }

        # Apply exclusions
        if ($ExcludePath) {
            $files = $files | Where-Object {
                $full = $_.FullName
                foreach ($ex in $ExcludePath) { if ($full -like $ex) { return $false } }
                return $true
            }
        }
        if ($MaxSizeMB -gt 0) {
            $maxBytes = [int64]$MaxSizeMB * 1MB
            $files    = $files | Where-Object { $_.Length -le $maxBytes }
        }

        $fileArray = @($files)
        $total     = $fileArray.Count
        Write-Host "[+] $total file(s) to audit" -ForegroundColor Green
        if ($total -eq 0) { continue }

        # --- Process -------------------------------------------------------------
        $collected = if ($Parallel) {
            $fileArray | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
                $block = $using:processBlock
                & $block $_ $using:Algorithm
            }
        }
        else {
            $i = 0
            $fileArray | ForEach-Object {
                $i++
                if ($i % 25 -eq 0 -or $i -eq $total) {
                    Write-Progress -Activity "Auditing $p" `
                                   -Status "$i / $total  ($($_.Name))" `
                                   -PercentComplete ([int](($i / $total) * 100))
                }
                & $script:processBlock $_ $Algorithm
            }
            Write-Progress -Activity "Auditing $p" -Completed
        }

        # --- Collect & filter ---------------------------------------------------
        $badStatuses = @('NotSigned', 'HashMismatch', 'UnknownError', 'NotTrusted')
        foreach ($row in $collected) {
            if ($row.Error) { $script:errors.Add("$($row.Path): $($row.Error)") }
            if ($OnlyUnsigned -and ($row.SigStatus -notin $badStatuses)) { continue }
            $script:results.Add($row)
        }
    }
}

end {
    $duration = (Get-Date) - $script:startTime
    $count    = $script:results.Count

    # --- Emit output ---------------------------------------------------------
    switch ($Format) {
        'Csv'      { $script:results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
        'Json'     { $script:results | ConvertTo-Json -Depth 4 | Set-Content -Path $OutputPath -Encoding UTF8 }
        'PassThru' { $script:results }
    }

    # --- Error log -----------------------------------------------------------
    if ($script:errors.Count -gt 0) {
        $script:errors | Set-Content -Path $ErrorLogPath -Encoding UTF8
    }

    # --- Summary -------------------------------------------------------------
    $signed   = ($script:results | Where-Object { $_.SigStatus -eq 'Valid' }).Count
    $badList  = @('NotSigned', 'HashMismatch', 'UnknownError', 'NotTrusted')
    $unsigned = ($script:results | Where-Object { $_.SigStatus -in $badList }).Count

    Write-Host ""
    Write-Host "================ AUDIT SUMMARY ================" -ForegroundColor Yellow
    Write-Host ("Files processed  : {0}" -f $count)
    Write-Host ("Valid signatures : {0}" -f $signed)   -ForegroundColor Green
    Write-Host ("Problematic sigs : {0}" -f $unsigned) -ForegroundColor $(if ($unsigned -gt 0) { 'Red' } else { 'Gray' })
    Write-Host ("Errors           : {0}" -f $script:errors.Count)
    Write-Host ("Duration         : {0:N1}s" -f $duration.TotalSeconds)
    if ($Format -ne 'PassThru') {
        Write-Host ("Output           : {0}" -f $OutputPath) -ForegroundColor Cyan
        if ($script:errors.Count -gt 0) {
            Write-Host ("Error log        : {0}" -f $ErrorLogPath) -ForegroundColor DarkYellow
        }
    }
    Write-Host "===============================================" -ForegroundColor Yellow

    # CI-friendly exit code when hunting unsigned binaries
    if ($OnlyUnsigned -and $unsigned -gt 0) { exit 2 }
}
