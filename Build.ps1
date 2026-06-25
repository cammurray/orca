<#
    .SYNOPSIS
        Stages the ORCA module for publishing to the PowerShell Gallery as ORCAPreview.

    .DESCRIPTION
        Copies the module source (ORCA.psm1, Checks, Outputs) into an output folder named
        after the module and generates a module manifest (.psd1) that mirrors the published
        ORCA manifest. Used by the GitHub release workflow to publish the preview channel.

    .PARAMETER Version
        The module version. A leading 'v' (e.g. from a git tag like v2.8.1) is stripped.

    .PARAMETER ModuleName
        The name of the module to produce. Defaults to ORCAPreview.

    .PARAMETER OutputDirectory
        Directory the staged module folder is created in. Defaults to ./output.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [string]$ModuleName = 'ORCAPreview',

    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'output')
)

$ErrorActionPreference = 'Stop'

# Normalise version (strip a leading v/V from git tags such as v2.8.1)
$Version = $Version.TrimStart('v', 'V')
if ([string]::IsNullOrWhiteSpace($Version)) {
    throw 'A version must be supplied.'
}

$stagePath = Join-Path $OutputDirectory $ModuleName
if (Test-Path $stagePath) {
    Remove-Item -Path $stagePath -Recurse -Force
}
New-Item -ItemType Directory -Path $stagePath -Force | Out-Null

# Copy module content
Copy-Item -Path (Join-Path $PSScriptRoot 'ORCA.psm1') -Destination $stagePath
Copy-Item -Path (Join-Path $PSScriptRoot 'Checks')    -Destination $stagePath -Recurse
Copy-Item -Path (Join-Path $PSScriptRoot 'Outputs')   -Destination $stagePath -Recurse

$readme = Join-Path $PSScriptRoot 'README.md'
if (Test-Path $readme) {
    Copy-Item -Path $readme -Destination $stagePath
}

# Build the FileList from the Checks and Outputs scripts (paths relative to the module root)
$fileList = Get-ChildItem -Path (Join-Path $stagePath 'Checks'), (Join-Path $stagePath 'Outputs') -Recurse -File -Filter '*.ps1' |
    ForEach-Object { $_.FullName.Substring($stagePath.Length + 1) }

$manifestPath = Join-Path $stagePath "$ModuleName.psd1"

New-ModuleManifest -Path $manifestPath `
    -ModuleVersion     $Version `
    -Guid              '17214386-e175-40e2-883a-8c0e41adf681' `
    -Author            'Microsoft' `
    -CompanyName       'Microsoft' `
    -Copyright         '(c) Microsoft. All rights reserved.' `
    -Description       'The Microsoft Defender for Office 365 Recommended Configuration Analyzer (ORCA) Module - Preview Release' `
    -PowerShellVersion '5.1' `
    -NestedModules     @('ORCA.psm1') `
    -FunctionsToExport @('Get-ORCAReport', 'Invoke-ORCA', 'Get-ORCAReportEmbeddedConfig') `
    -CmdletsToExport   @() `
    -VariablesToExport '*' `
    -AliasesToExport   @() `
    -FileList          $fileList `
    -ProjectUri        'https://github.com/cammurray/orca' `
    -Tags              @('Microsoft', 'Office365', 'Security', 'ORCA', 'Defender', 'Preview')

# Validate the staged module before it leaves the build
Test-ModuleManifest -Path $manifestPath | Out-Null

Write-Host "Built $ModuleName $Version at $stagePath"
