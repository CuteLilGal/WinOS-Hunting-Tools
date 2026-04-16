# Invoke-FileAudit

A PowerShell script for auditing binaries (DLL, EXE, SYS, ...) on Windows. Collects cryptographic hash, Authenticode signature, version info, and file metadata into CSV / JSON. Built for enterprise software inventory, supply-chain auditing, and unsigned-binary hunting.

## Features

- **Full metadata per file** - SHA256 hash, signature status, signer certificate details, file version, company, original filename, timestamps
- **Flexible scope** - single folder or recursive, any extension pattern, exclude filters
- **Multiple output formats** - CSV, JSON, or pipeline objects
- **Fast** - parallel processing on PowerShell 7+, provider-level `-Filter` where possible
- **CI-friendly** - `-OnlyUnsigned` mode with non-zero exit code for pipeline gates
- **Discoverable** - full `Get-Help` support with examples

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+ (7+ required for `-Parallel`)
- Administrator privileges recommended for scanning system folders

## Quick start

```powershell
# Default: audit C:\Windows\System32\*.dll
.\Invoke-FileAudit.ps1

# Scan a specific folder recursively
.\Invoke-FileAudit.ps1 -r "C:\Downloads"

# Hunt unsigned binaries under Program Files
.\Invoke-FileAudit.ps1 "C:\Program Files" -r -Extension *.dll,*.exe -OnlyUnsigned

# Parallel scan, JSON output
.\Invoke-FileAudit.ps1 -r "D:\App" -Parallel -Format Json
```

If script execution is blocked:

```powershell
powershell -ExecutionPolicy Bypass -File .\Invoke-FileAudit.ps1 -r "C:\Path"
```

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Path` | `string[]` | `C:\Windows\System32` | Folder(s) to scan. Positional, pipeline-bindable. |
| `-Recurse` / `-r` | `switch` | off | Recurse into subdirectories |
| `-Extension` | `string[]` | `*.dll` | File patterns, e.g. `*.dll,*.exe,*.sys` |
| `-OutputPath` | `string` | auto-timestamped | Output file path |
| `-Format` | `Csv \| Json \| PassThru` | `Csv` | Output format |
| `-Algorithm` | `MD5 \| SHA1 \| SHA256 \| SHA384 \| SHA512` | `SHA256` | Hash algorithm |
| `-OnlyUnsigned` | `switch` | off | Emit only problematic signatures; exit 2 if any found |
| `-ExcludePath` | `string[]` | - | Wildcard patterns to skip, e.g. `*\WinSxS\*` |
| `-MaxSizeMB` | `int` | 0 (no limit) | Skip files larger than this |
| `-Parallel` | `switch` | off | Use `ForEach-Object -Parallel` (PS 7+) |
| `-ThrottleLimit` | `int` | 8 | Max concurrent threads when `-Parallel` |

Run `Get-Help .\Invoke-FileAudit.ps1 -Examples` for more usage patterns.

## Output

Each row contains: `Path`, `FileName`, `Size`, timestamps, `Hash`, `SigStatus`, `Signer`, `Issuer`, `Thumbprint`, `NotBefore`/`NotAfter`, `FileVersion`, `CompanyName`, `OriginalFilename`, and more.

Errors are written to a sibling `.errors.log` file. A summary is printed at the end (total, signed, unsigned, errors, duration).

## Use cases

- **Software inventory** - baseline what's deployed on a fleet machine
- **Threat hunting** - find unsigned or suspiciously-signed binaries in user-writable locations
- **Supply-chain audit** - compare hashes against a known-good baseline
- **CI gate** - fail builds that emit unsigned DLLs:

  ```powershell
  .\Invoke-FileAudit.ps1 -Path .\bin -r -OnlyUnsigned
  if ($LASTEXITCODE -eq 2) { throw "Unsigned binaries in build output" }
  ```
