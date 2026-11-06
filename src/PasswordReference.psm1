#Requires -Version 7.2
Set-StrictMode -Version Latest

function ConvertTo-BannedTermSet {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Terms)

    $unique = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
    foreach ($value in $Terms) {
        if ($value -isnot [string]) { throw 'Every term must be a string.' }
        $term = $value.Trim().ToLowerInvariant()
        if ($term.Length -eq 0) { throw 'Blank terms are not valid reference or tenant entries.' }
        if ($term -match '[\x00-\x1f\x7f;]') { throw 'Terms must not contain control characters or semicolons.' }
        if ($term.Length -lt 4 -or $term.Length -gt 16) {
            throw 'Each trimmed term must contain 4 to 16 characters.'
        }
        # These substitutions compare configured terms. This is not a password evaluator.
        $term = $term.Replace('0', 'o').Replace('1', 'l').Replace('$', 's').Replace('@', 'a')
        [void]$unique.Add($term)
    }
    if ($unique.Count -gt 1000) { throw 'A custom list supports at most 1000 distinct normalized terms.' }
    foreach ($term in $unique) { $term }
}

function Assert-PasswordReference {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Reference)
    if (-not $Reference.Contains('schemaVersion') -or
        ($Reference['schemaVersion'] -isnot [int] -and $Reference['schemaVersion'] -isnot [long]) -or
        $Reference['schemaVersion'] -ne 1) { throw 'Expected numeric schemaVersion 1.' }
    if (-not $Reference.Contains('version') -or $Reference['version'] -isnot [string] -or
        [string]::IsNullOrWhiteSpace($Reference['version'])) { throw 'A reference version is required.' }
    if (-not $Reference.Contains('terms') -or $Reference['terms'] -isnot [array]) {
        throw 'Reference terms must be a JSON array of strings.'
    }
    $normalized = @(ConvertTo-BannedTermSet -Terms $Reference['terms'])
    if ($normalized.Count -eq 0) { throw 'An empty reference cannot establish coverage.' }
}

function Read-PasswordReference {
    [CmdletBinding(DefaultParameterSetName = 'File')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'File')][string]$Path,
        [Parameter(Mandatory, ParameterSetName = 'Uri')][uri]$Uri
    )
    if ($PSCmdlet.ParameterSetName -eq 'Uri') {
        if (-not $Uri.IsAbsoluteUri -or $Uri.Scheme -ne 'https' -or $Uri.UserInfo) {
            throw 'Use an absolute HTTPS reference URL without embedded credentials.'
        }
        $response = Invoke-WebRequest -Uri $Uri -Method Get -TimeoutSec 20 -MaximumRedirection 3 -ErrorAction Stop
        $json = $response.Content
    } else {
        $json = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    }
    $reference = ConvertFrom-Json -InputObject $json -AsHashtable -ErrorAction Stop
    if ($reference -isnot [System.Collections.IDictionary]) { throw 'The reference must be a JSON object.' }
    Assert-PasswordReference -Reference $reference
    return $reference
}

function New-CoverageResult {
    param(
        [string]$Status, [string]$Reason,
        [string]$ReferenceVersion = '',
        [string[]]$Expected = @(), [string[]]$Configured = @(),
        [string[]]$Missing = @(), [string[]]$Extra = @(),
        [string]$Detail = ''
    )
    [pscustomobject][ordered]@{
        Status = $Status
        Scope = 'Custom banned-password reference coverage'
        Reason = $Reason
        ReferenceVersion = $ReferenceVersion
        ExpectedCount = $Expected.Count
        ConfiguredCount = $Configured.Count
        MissingTerms = @($Missing)
        ExtraTerms = @($Extra)
        Detail = $Detail
    }
}

function Compare-PasswordReference {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Reference,
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()][object[]]$ConfiguredTerms
    )
    try {
        Assert-PasswordReference -Reference $Reference
        if ($null -eq $ConfiguredTerms) { throw 'Configured terms were not collected.' }
        $expected = @(ConvertTo-BannedTermSet -Terms $Reference['terms'])
        $configured = @(ConvertTo-BannedTermSet -Terms $ConfiguredTerms)
        $missing = @($expected | Where-Object { $_ -cnotin $configured })
        $extra = @($configured | Where-Object { $_ -cnotin $expected })
        $state = if ($missing.Count -eq 0) { 'Passed' } else { 'Failed' }
        $reason = if ($missing.Count -eq 0) { 'ReferenceCovered' } else { 'RequiredTermsMissing' }
        New-CoverageResult -Status $state -Reason $reason -ReferenceVersion $Reference['version'] `
            -Expected $expected -Configured $configured -Missing $missing -Extra $extra
    } catch {
        New-CoverageResult -Status 'NotAssessed' -Reason 'InvalidOrMissingEvidence' -Detail $_.Exception.Message
    }
}

function Get-EntraBannedPasswordEvidence {
    [CmdletBinding()]
    param()
    # Deliberately uses an existing Global-cloud context. It never signs in or writes settings.
    $context = Get-MgContext -ErrorAction Stop
    if ($null -eq $context -or $context.Environment -ne 'Global') {
        throw 'An existing Microsoft Graph Global-cloud connection is required.'
    }
    $next = 'https://graph.microsoft.com/beta/settings'
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $settings = [System.Collections.Generic.List[object]]::new()
    while ($next) {
        $pageUri = [uri]$next
        if ($pageUri.Scheme -ne 'https' -or $pageUri.Host -ne 'graph.microsoft.com' -or
            $pageUri.Port -ne 443 -or $pageUri.UserInfo -or -not $pageUri.AbsolutePath.StartsWith('/beta/')) {
            throw 'Unexpected Graph pagination destination.'
        }
        if (-not $seen.Add($next) -or $seen.Count -gt 100) { throw 'Graph pagination did not complete.' }
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType Hashtable -ErrorAction Stop
        if (-not $page.Contains('value') -or $page['value'] -isnot [array]) {
            throw 'Graph did not return a complete settings collection.'
        }
        foreach ($setting in $page['value']) { $settings.Add($setting) }
        $next = if ($page.Contains('@odata.nextLink')) { [string]$page['@odata.nextLink'] } else { '' }
    }
    $policies = @($settings | Where-Object { $_['displayName'] -eq 'Password Rule Settings' })
    if ($policies.Count -ne 1) { throw 'Expected exactly one Password Rule Settings object.' }
    if (-not $policies[0].Contains('values')) { throw 'Password rule values are missing.' }
    $entries = @($policies[0]['values'] | Where-Object { $_['name'] -eq 'BannedPasswordList' })
    if ($entries.Count -ne 1 -or -not $entries[0].Contains('value') -or $entries[0]['value'] -isnot [string]) {
        throw 'BannedPasswordList was not collected completely.'
    }
    @{ bannedPasswordList = $entries[0]['value'] }
}

function Invoke-PasswordReferenceCheck {
    [CmdletBinding()]
    param(
        [string]$ReferencePath,
        [uri]$ReferenceUri,
        [string]$SettingsPath,
        [switch]$Live
    )
    try {
        if ($ReferenceUri) { $reference = Read-PasswordReference -Uri $ReferenceUri }
        elseif ($ReferencePath) { $reference = Read-PasswordReference -Path $ReferencePath }
        else { throw 'Supply a reference file or reference URL.' }
    } catch {
        return New-CoverageResult -Status 'NotAssessed' -Reason 'ReferenceUnavailableOrInvalid' -Detail $_.Exception.Message
    }
    try {
        if ($Live) { $evidence = Get-EntraBannedPasswordEvidence }
        elseif ($SettingsPath) {
            $evidence = Get-Content -LiteralPath $SettingsPath -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        } else { throw 'Supply a fixture file or explicitly choose -Live.' }
        if ($evidence -isnot [System.Collections.IDictionary] -or -not $evidence.Contains('bannedPasswordList') -or
            $evidence['bannedPasswordList'] -isnot [string]) { throw 'A collected bannedPasswordList string is required.' }
        $value = $evidence['bannedPasswordList']
        # A present empty string is known empty configuration. A missing/null field is unknown evidence.
        [object[]]$terms = @()
        if (-not [string]::IsNullOrWhiteSpace($value)) { $terms = @($value -split ';') }
        Compare-PasswordReference -Reference $reference -ConfiguredTerms $terms
    } catch {
        New-CoverageResult -Status 'NotAssessed' -Reason 'CollectionUnavailableOrInvalid' -Detail $_.Exception.Message
    }
}

Export-ModuleMember -Function ConvertTo-BannedTermSet, Read-PasswordReference, Compare-PasswordReference, Invoke-PasswordReferenceCheck
