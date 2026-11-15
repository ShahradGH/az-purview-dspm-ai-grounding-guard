# Invoke-SharePointOversharingQuarantine.ps1
<#
.SYNOPSIS
    Audits SharePoint site permissions via Microsoft Graph v2.x, revokes overshared EEEU/Anyone links,
    and dispatches a CISO Adaptive Card to Microsoft Teams.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [PSCustomObject]$AuditVerdict,

    [Parameter(Mandatory)]
    [string]$SiteId,

    [Parameter(Mandatory)]
    [string]$TeamId,

    [Parameter(Mandatory)]
    [string]$ChannelId,

    [Parameter()]
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$permissionsUri = "https://graph.microsoft.com/v1.0/sites/$SiteId/permissions"
$teamsUri = "https://graph.microsoft.com/v1.0/teams/$TeamId/channels/$ChannelId/messages"

$cisoCard = [ordered]@{
    type    = 'AdaptiveCard'
    version = '1.5'
    body    = @(
        @{
            type   = 'TextBlock'
            text   = "Purview DSPM for AI: Grounding Quarantine ($($AuditVerdict.Decision))"
            weight = 'Bolder'
            size   = 'Medium'
            color  = 'Attention'
        }
        @{
            type  = 'FactSet'
            facts = @(
                @{ title = 'Case ID'; value = $AuditVerdict.CaseId }
                @{ title = 'SharePoint Site'; value = $AuditVerdict.SiteUrl }
                @{ title = 'Chunk ID'; value = $AuditVerdict.ChunkId }
                @{ title = 'Purview Label'; value = $AuditVerdict.PurviewLabel }
                @{ title = 'Requires Quarantine'; value = "$($AuditVerdict.RequiresSiteQuarantine)" }
            )
        }
        @{
            type = 'TextBlock'
            text = $AuditVerdict.Reason
            wrap = $true
        }
    )
    actions = @(
        @{
            type  = 'Action.Submit'
            title = 'Enforce Restricted SharePoint Search (RSS)'
            data  = @{ action = 'enforce_rss_quarantine'; siteId = $SiteId }
        }
        @{
            type  = 'Action.Submit'
            title = 'Re-index AI Search after ACL Fix'
            data  = @{ action = 'reindex_ai_search'; siteId = $SiteId }
        }
    )
}

$attachmentId = [guid]::NewGuid().ToString()
$teamsPayload = [ordered]@{
    body = @{
        contentType = 'html'
        content     = "<attachment id=`"$attachmentId`"></attachment>"
    }
    attachments = @(
        @{
            id          = $attachmentId
            contentType = 'application/vnd.microsoft.card.adaptive'
            content     = ($cisoCard | ConvertTo-Json -Depth 12 -Compress)
        }
    )
}

if ($DryRun) {
    return [PSCustomObject]@{
        Status         = 'DRY_RUN_PREPARED'
        PermissionsUri = $permissionsUri
        TeamsUri       = $teamsUri
        AttachmentId   = $attachmentId
        TeamsPayload   = $teamsPayload
    }
}

$revokedCount = 0
if ($AuditVerdict.RequiresSiteQuarantine) {
    $perms = Invoke-MgGraphRequest -Method GET -Uri $permissionsUri
    foreach ($p in @($perms.value)) {
        if ($p.roles -contains 'read' -and ($p.grantedToIdentitiesV2.siteUser.loginName -match 'spo-grid-all-users|everyone')) {
            Invoke-MgGraphRequest -Method DELETE -Uri "$permissionsUri/$($p.id)" | Out-Null
            $revokedCount++
        }
    }
}

$teamsResp = Invoke-MgGraphRequest -Method POST -Uri $teamsUri -Body ($teamsPayload | ConvertTo-Json -Depth 12) -ContentType 'application/json'

return [PSCustomObject]@{
    Status             = 'QUARANTINE_AND_ALERT_EXECUTED'
    PermissionsRevoked = $revokedCount
    TeamsMessageId     = $teamsResp.id
    TeamsUri           = $teamsUri
}
