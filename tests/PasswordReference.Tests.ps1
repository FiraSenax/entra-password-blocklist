BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../src/PasswordReference.psm1') -Force
    $root = Split-Path $PSScriptRoot
    $reference = Read-PasswordReference -Path (Join-Path $root 'references/demo.json')
}

Describe 'Reference normalization and coverage' {
    It 'normalizes case, surrounding whitespace, documented substitutions and duplicates' {
        $result = @(ConvertTo-BannedTermSet -Terms @(' H@RBOR ', 'ORI0N', 'orion', 'CEDAR', 'cedar', 'C1oud', '$tarlab'))
        ($result -join ',') | Should -Be 'cedar,cloud,harbor,orion,starlab'
    }
    It 'does not remove meaningful characters or spaces inside a term' {
        $result = @(ConvertTo-BannedTermSet -Terms @('north star', 'north-star', 'northstar'))
        $result.Count | Should -Be 3
    }
    It 'identifies the missing term while allowing extra tenant terms' {
        $result = Invoke-PasswordReferenceCheck -ReferencePath "$root/references/demo.json" -SettingsPath "$root/examples/fixtures/missing-term.json"
        $result.Status | Should -Be 'Failed'
        ($result.MissingTerms -join ',') | Should -Be 'orion'
        ($result.ExtraTerms -join ',') | Should -Be 'extra'
    }
    It 'passes when differently written configured terms cover the reference' {
        $result = Invoke-PasswordReferenceCheck -ReferencePath "$root/references/demo.json" -SettingsPath "$root/examples/fixtures/covered.json"
        $result.Status | Should -Be 'Passed'
        $result.ExpectedCount | Should -Be 3
        $result.MissingTerms.Count | Should -Be 0
    }
    It 'treats a known empty list as a failed comparison' {
        $result = Compare-PasswordReference -Reference $reference -ConfiguredTerms @()
        $result.Status | Should -Be 'Failed'
        $result.MissingTerms.Count | Should -Be 3
    }
    It 'treats an uncollected list as unassessed' {
        (Compare-PasswordReference -Reference $reference -ConfiguredTerms $null).Status | Should -Be 'NotAssessed'
    }
    It 'rejects invalid terms instead of silently dropping them' -ForEach @(
        @{ Terms = @('abc') },
        @{ Terms = @('abcdefghijklmnopq') },
        @{ Terms = @('   ') },
        @{ Terms = @('cedar;orion') },
        @{ Terms = @("cedar`norion") },
        @{ Terms = @(1234) },
        @{ Terms = @($null) }
    ) {
        { ConvertTo-BannedTermSet -Terms $Terms } | Should -Throw
    }
    It 'accepts length boundaries and rejects more than 1000 distinct terms' {
        @(ConvertTo-BannedTermSet -Terms @('abcd', 'abcdefghijklmnop')).Count | Should -Be 2
        # Letters avoid normalization collapsing digit variants.
        $many = @(0..1000 | ForEach-Object {
            'term' + [char][int](97 + [math]::Floor($_ / 676)) + [char][int](97 + [math]::Floor(($_ % 676) / 26)) + [char][int](97 + ($_ % 26))
        })
        { ConvertTo-BannedTermSet -Terms $many } | Should -Throw '*1000*'
    }
    It 'rejects an empty reference instead of returning a vacuous pass' {
        $empty = @{ schemaVersion = 1; version = '1.0'; terms = @() }
        (Compare-PasswordReference -Reference $empty -ConfiguredTerms @('cedar')).Status | Should -Be 'NotAssessed'
    }
    It 'validates the curated starter reference' {
        $starter = Read-PasswordReference -Path "$root/references/blocklist.json"
        @(ConvertTo-BannedTermSet -Terms $starter['terms']).Count | Should -Be 20
    }
}

Describe 'Reference retrieval and incomplete evidence' {
    It 'fetches a JSON reference through the configured HTTPS source' {
        Mock Invoke-WebRequest -ModuleName PasswordReference {
            [pscustomobject]@{ Content = '{"schemaVersion":1,"version":"test","terms":["orion"]}' }
        }
        $loaded = Read-PasswordReference -Uri 'https://example.org/reference.json'
        $loaded['version'] | Should -Be 'test'
        Should -Invoke Invoke-WebRequest -ModuleName PasswordReference -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'Get' -and $Uri.AbsoluteUri -eq 'https://example.org/reference.json'
        }
    }
    It 'does not turn an unavailable source into a green result' {
        Mock Invoke-WebRequest -ModuleName PasswordReference { throw 'Reference unavailable' }
        $result = Invoke-PasswordReferenceCheck -ReferenceUri 'https://example.org/reference.json' -SettingsPath "$root/examples/fixtures/covered.json"
        $result.Status | Should -Be 'NotAssessed'
        $result.Reason | Should -Be 'ReferenceUnavailableOrInvalid'
    }
    It 'rejects unsupported transport and embedded credentials' -ForEach @(
        @{ Uri = 'http://example.org/reference.json' },
        @{ Uri = 'https://user:password@example.org/reference.json' }
    ) {
        { Read-PasswordReference -Uri $Uri } | Should -Throw '*HTTPS*'
    }
    It 'rejects malformed or incompatible reference documents' -ForEach @(
        @{ Json = '{broken' },
        @{ Json = '{"schemaVersion":2,"version":"x","terms":["orion"]}' },
        @{ Json = '{"schemaVersion":"1","version":"x","terms":["orion"]}' },
        @{ Json = '{"schemaVersion":1,"version":"x","terms":"orion"}' },
        @{ Json = '{"schemaVersion":1,"version":"x","terms":[]}' },
        @{ Json = '{"schemaVersion":1,"terms":["orion"]}' }
    ) {
        $path = Join-Path $TestDrive 'reference.json'
        Set-Content -LiteralPath $path -Value $Json
        (Invoke-PasswordReferenceCheck -ReferencePath $path -SettingsPath "$root/examples/fixtures/covered.json").Status | Should -Be 'NotAssessed'
    }
    It 'distinguishes a present empty string from missing or null evidence' {
        $path = Join-Path $TestDrive 'settings.json'
        Set-Content $path '{"bannedPasswordList":""}'
        (Invoke-PasswordReferenceCheck -ReferencePath "$root/references/demo.json" -SettingsPath $path).Status | Should -Be 'Failed'
        foreach ($bad in @('{}', '{"bannedPasswordList":null}', '{"bannedPasswordList":false}')) {
            Set-Content $path $bad
            (Invoke-PasswordReferenceCheck -ReferencePath "$root/references/demo.json" -SettingsPath $path).Status | Should -Be 'NotAssessed'
        }
    }
}

Describe 'Read-only Graph collection' {
    BeforeAll {
        # Test-only command stubs. No sign-in and no tenant requests are made.
        InModuleScope PasswordReference {
            function script:Get-MgContext { throw 'No test context configured' }
            function script:Invoke-MgGraphRequest { param($Method, $Uri, $OutputType) throw 'No test response configured' }
        }
    }
    AfterAll {
        InModuleScope PasswordReference {
            Remove-Item Function:script:Get-MgContext, Function:script:Invoke-MgGraphRequest -ErrorAction SilentlyContinue
        }
    }
    BeforeEach {
        Mock Get-MgContext -ModuleName PasswordReference { [pscustomobject]@{ Environment = 'Global' } }
        Mock Invoke-MgGraphRequest -ModuleName PasswordReference {
            @{ value = @(@{ displayName = 'Password Rule Settings'; values = @(@{ name = 'BannedPasswordList'; value = 'cedar;orion;harbor' }) }) }
        }
    }
    It 'reads settings and compares them without writing any tenant data' {
        (Invoke-PasswordReferenceCheck -ReferencePath "$root/references/demo.json" -Live).Status | Should -Be 'Passed'
        Should -Invoke Invoke-MgGraphRequest -ModuleName PasswordReference -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'GET' -and $Uri -eq 'https://graph.microsoft.com/beta/settings'
        }
    }
    It 'leaves incomplete policy evidence unassessed' {
        Mock Invoke-MgGraphRequest -ModuleName PasswordReference { @{ value = @(@{ displayName = 'Password Rule Settings'; values = @() }) } }
        (Invoke-PasswordReferenceCheck -ReferencePath "$root/references/demo.json" -Live).Status | Should -Be 'NotAssessed'
    }
    It 'completes pagination before selecting the password settings' {
        Mock Invoke-MgGraphRequest -ModuleName PasswordReference {
            if ($Uri -eq 'https://graph.microsoft.com/beta/settings') {
                @{ value = @(@{ displayName = 'Other settings' }); '@odata.nextLink' = 'https://graph.microsoft.com/beta/settings?$skiptoken=next' }
            } else {
                @{ value = @(@{ displayName = 'Password Rule Settings'; values = @(@{ name = 'BannedPasswordList'; value = 'cedar;orion;harbor' }) }) }
            }
        }
        (Invoke-PasswordReferenceCheck -ReferencePath "$root/references/demo.json" -Live).Status | Should -Be 'Passed'
        Should -Invoke Invoke-MgGraphRequest -ModuleName PasswordReference -Times 2 -Exactly
    }
    It 'leaves request failures unassessed' {
        Mock Invoke-MgGraphRequest -ModuleName PasswordReference { throw 'Forbidden' }
        (Invoke-PasswordReferenceCheck -ReferencePath "$root/references/demo.json" -Live).Status | Should -Be 'NotAssessed'
    }
    It 'does not send the Graph context to an unexpected pagination host' {
        Mock Invoke-MgGraphRequest -ModuleName PasswordReference { @{ value = @(); '@odata.nextLink' = 'https://example.org/beta/settings' } }
        (Invoke-PasswordReferenceCheck -ReferencePath "$root/references/demo.json" -Live).Status | Should -Be 'NotAssessed'
        Should -Invoke Invoke-MgGraphRequest -ModuleName PasswordReference -Times 1 -Exactly
    }
    It 'rejects non-Global cloud contexts rather than guessing the endpoint' {
        Mock Get-MgContext -ModuleName PasswordReference { [pscustomobject]@{ Environment = 'USGov' } }
        (Invoke-PasswordReferenceCheck -ReferencePath "$root/references/demo.json" -Live).Status | Should -Be 'NotAssessed'
        Should -Invoke Invoke-MgGraphRequest -ModuleName PasswordReference -Times 0 -Exactly
    }
}

Describe 'Published PowerShell syntax' {
    It 'parses every script and module' {
        foreach ($file in Get-ChildItem $root -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1' }) {
            $tokens = $null; $parseErrors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors)
            @($parseErrors).Count | Should -Be 0 -Because $file.FullName
        }
    }
}
