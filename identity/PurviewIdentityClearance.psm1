<#
.SYNOPSIS
    Microsoft Graph v2.x Entra ID clearance and SharePoint oversharing governance module.
.DESCRIPTION
    Resolves caller Entra ID security group clearance tiers for Purview sensitivity-label
    grounding enforcement, detects external guest or EEEU exposure on AI-indexed SharePoint
    sites, and revokes oversharing grants via Microsoft Graph v1.0.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-PurviewGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter()]
        [object]$Body,

        [Parameter()]
        [scriptblock]$GraphInvoker
    )

    if ($null -ne $GraphInvoker) {
        return & $GraphInvoker $Method $Uri $Body
    }

    $params = @{
        Method = $Method
        Uri    = $Uri
    }
    if ($null -ne $Body) {
        $params['Body'] = ($Body | ConvertTo-Json -Depth 10)
        $params['ContentType'] = 'application/json'
    }

    return Invoke-MgGraphRequest @params
}

function Get-EntraCallerClearanceTier {
    <#
    .SYNOPSIS
        Maps a RAG or Copilot caller's Entra ID transitive group memberships to a Purview sensitivity clearance rank.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter()]
        [scriptblock]$GraphInvoker
    )

    $encoded = [System.Uri]::EscapeDataString($UserPrincipalName)
    $uri = "https://graph.microsoft.com/v1.0/users/$encoded/transitiveMemberOf?`$select=id,displayName"
    $resp = Invoke-PurviewGraphRequest -Method 'GET' -Uri $uri -GraphInvoker $GraphInvoker
    $groups = @($resp.value | ForEach-Object { $_.displayName })

    $tier = 'General'
    $rank = 1
    if ($groups -contains 'SG-Clearance-HighlyConfidential') {
        $tier = 'Highly Confidential'
        $rank = 3
    }
    elseif ($groups -contains 'SG-Clearance-Confidential') {
        $tier = 'Confidential'
        $rank = 2
    }

    return [PSCustomObject]@{
        UserPrincipalName = $UserPrincipalName
        MaxLabelTier      = $tier
        ClearanceRank     = $rank
        MatchedGroups     = @($groups | Where-Object { $_ -like 'SG-Clearance-*' })
        EvaluatedAtUtc    = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Test-SharePointSiteGuestExposure {
    <#
    .SYNOPSIS
        Audits a SharePoint site's Microsoft Graph permissions for EEEU or broad external sharing links.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SiteId,

        [Parameter()]
        [scriptblock]$GraphInvoker
    )

    $uri = "https://graph.microsoft.com/v1.0/sites/$SiteId/permissions"
    $resp = Invoke-PurviewGraphRequest -Method 'GET' -Uri $uri -GraphInvoker $GraphInvoker
    $perms = @($resp.value)

    $overshared = @($perms | Where-Object {
        $roles = @($_.roles) -join ','
        $identities = ($_.grantedToIdentitiesV2 | ConvertTo-Json -Compress -ErrorAction SilentlyContinue)
        $identities -match 'spo-grid-all-users|everyone|EveryoneExceptExternalUsers' -or $roles -match 'fullControl'
    })

    return [PSCustomObject]@{
        SiteId               = $SiteId
        TotalPermissions     = $perms.Count
        OversharedGrantCount = $overshared.Count
        OversharedGrantIds   = @($overshared | ForEach-Object { $_.id })
        SafeForAiGrounding   = ($overshared.Count -eq 0)
        AuditedAtUtc         = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Revoke-SharePointOversharingGrant {
    <#
    .SYNOPSIS
        Revokes an overshared SharePoint site permission grant via Microsoft Graph v1.0 DELETE.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$SiteId,

        [Parameter(Mandatory)]
        [string]$PermissionId,

        [Parameter()]
        [scriptblock]$GraphInvoker
    )

    $uri = "https://graph.microsoft.com/v1.0/sites/$SiteId/permissions/$PermissionId"
    if (-not $PSCmdlet.ShouldProcess("$SiteId/$PermissionId", 'Revoke overshared SharePoint permission')) {
        return [PSCustomObject]@{
            SiteId       = $SiteId
            PermissionId = $PermissionId
            Revoked      = $false
            Status       = 'WHATIF-DRYRUN'
        }
    }

    $null = Invoke-PurviewGraphRequest -Method 'DELETE' -Uri $uri -GraphInvoker $GraphInvoker
    return [PSCustomObject]@{
        SiteId       = $SiteId
        PermissionId = $PermissionId
        Revoked      = $true
        RevokedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
}

Export-ModuleMember -Function @(
    'Get-EntraCallerClearanceTier',
    'Test-SharePointSiteGuestExposure',
    'Revoke-SharePointOversharingGrant'
)
