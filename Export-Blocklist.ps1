#Requires -Version 7.2
[CmdletBinding()]
param([string]$ReferencePath = (Join-Path $PSScriptRoot 'references/blocklist.json'))
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'src/PasswordReference.psm1') -Force
$reference = Read-PasswordReference -Path $ReferencePath
ConvertTo-BannedTermSet -Terms $reference['terms']
