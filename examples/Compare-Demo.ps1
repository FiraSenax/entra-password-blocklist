#Requires -Version 7.2
[CmdletBinding()]
param([uri]$ReferenceUri)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../src/PasswordReference.psm1') -Force
$referenceArgs = if ($ReferenceUri) {
    @{ ReferenceUri = $ReferenceUri }
} else {
    @{ ReferencePath = Join-Path $PSScriptRoot '../references/demo.json' }
}
foreach ($fixture in @('missing-term', 'covered')) {
    $result = Invoke-PasswordReferenceCheck @referenceArgs -SettingsPath (Join-Path $PSScriptRoot "fixtures/$fixture.json")
    [pscustomobject]@{ Scenario = $fixture; Result = $result } | ConvertTo-Json -Depth 6
}
