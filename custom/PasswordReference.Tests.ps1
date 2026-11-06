#Requires -Version 7.2
# Run through Maester with an already authenticated Microsoft Graph context.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../src/PasswordReference.psm1') -Force
}

Describe 'Custom banned-password reference coverage' -Tag 'Custom', 'PasswordReference' {
    It 'REF.PWD.001: Contains every required reference term' {
        if ($env:PASSWORD_REFERENCE_URI) {
            $source = @{ ReferenceUri = [uri]$env:PASSWORD_REFERENCE_URI }
        } else {
            $source = @{ ReferencePath = Join-Path $PSScriptRoot '../references/blocklist.json' }
        }
        $result = Invoke-PasswordReferenceCheck @source -Live
        $detail = "Reference: $($result.ReferenceVersion)`n`nCoverage: $($result.Status)`n`nMissing: $($result.MissingTerms -join ', ')`n`n$($result.Detail)"
        Add-MtTestResultDetail -Description 'All required organisation-specific reference terms must be present in the custom banned-password list.' -Result $detail
        if ($result.Status -eq 'NotAssessed') {
            Set-ItResult -Skipped -Because "$($result.Reason): $($result.Detail)"
            return
        }
        $result.Status | Should -Be 'Passed' -Because "missing reference terms: $($result.MissingTerms -join ', ')"
    }
}
