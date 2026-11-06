#Requires -Version 7.2
[CmdletBinding()]
param(
    [string]$ReferencePath = (Join-Path $PSScriptRoot 'references/demo.json'),
    [uri]$ReferenceUri,
    [string]$SettingsPath = (Join-Path $PSScriptRoot 'examples/fixtures/covered.json'),
    [switch]$Live
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'src/PasswordReference.psm1') -Force
$params = @{ SettingsPath = $SettingsPath; Live = $Live }
if ($ReferenceUri) { $params.ReferenceUri = $ReferenceUri } else { $params.ReferencePath = $ReferencePath }
$result = Invoke-PasswordReferenceCheck @params
$result | ConvertTo-Json -Depth 6
switch ($result.Status) {
    'Passed' { exit 0 }
    'Failed' { exit 1 }
    default { exit 2 }
}
