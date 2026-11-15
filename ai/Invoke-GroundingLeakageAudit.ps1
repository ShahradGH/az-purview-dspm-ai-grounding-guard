# Invoke-GroundingLeakageAudit.ps1
<#
.SYNOPSIS
    Audits Azure AI Search / Foundry grounding chunks against Microsoft Purview sensitivity labels and SharePoint oversharing posture.
.DESCRIPTION
    Enforces four deterministic epistemic & DSPM boundaries before a chunk enters the Foundry LLM context window:
    1. Indirect prompt-injection quarantine via Test-PromptInjectionSensitivityBoundary.ps1.
    2. Purview sensitivity label hierarchy check against caller Entra clearance.
    3. Fail-closed abstention on unlabeled chunks originating from overshared (EEEU/Anyone) SharePoint sites.
    4. Immediate quarantine escalation for Highly Confidential oversharing exposure.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [PSCustomObject]$GroundingCase
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$boundaryScript = Join-Path $PSScriptRoot 'Test-PromptInjectionSensitivityBoundary.ps1'

$labelRank = @{
    'Public'              = 1
    'General'             = 2
    'Confidential'        = 3
    'Highly Confidential' = 4
}

# 1. Indirect Prompt-Injection Boundary on Retrieved RAG Text
$injResult = & $boundaryScript -ChunkText $GroundingCase.chunkText -ChunkId $GroundingCase.chunkId
if ($injResult.InjectionDetected) {
    return [PSCustomObject]@{
        CaseId               = $GroundingCase.caseId
        ChunkId              = $GroundingCase.chunkId
        SiteUrl              = $GroundingCase.siteUrl
        PurviewLabel         = $GroundingCase.purviewLabel
        Decision             = 'QUARANTINE_INDIRECT_PROMPT_INJECTION'
        PermittedForGrounding = $false
        RequiresSiteQuarantine = $true
        Reason               = 'Retrieved RAG chunk contains indirect prompt-injection attempting to bypass Purview labels.'
    }
}

# 2. Fail-Closed Abstention for Unlabeled Content on Overshared Sites
if ($GroundingCase.purviewLabel -eq 'Unlabeled' -and $GroundingCase.hasEveryoneExceptExternalLink) {
    return [PSCustomObject]@{
        CaseId                 = $GroundingCase.caseId
        ChunkId                = $GroundingCase.chunkId
        SiteUrl                = $GroundingCase.siteUrl
        PurviewLabel           = $GroundingCase.purviewLabel
        Decision               = 'ABSTAIN_UNLABELED_OVERSHARED_SITE'
        PermittedForGrounding  = $false
        RequiresSiteQuarantine = $true
        Reason                 = 'Chunk lacks a Purview sensitivity label and originates from an EveryoneExceptExternalUsers (EEEU) site.'
    }
}

$chunkRank = $labelRank[$GroundingCase.purviewLabel]
$callerRank = $labelRank[$GroundingCase.callerClearanceLevel]

if ($null -eq $chunkRank -or $null -eq $callerRank) {
    return [PSCustomObject]@{
        CaseId                 = $GroundingCase.caseId
        ChunkId                = $GroundingCase.chunkId
        SiteUrl                = $GroundingCase.siteUrl
        PurviewLabel           = $GroundingCase.purviewLabel
        Decision               = 'ABSTAIN_UNKNOWN_LABEL_TAXONOMY'
        PermittedForGrounding  = $false
        RequiresSiteQuarantine = $false
        Reason                 = 'Unrecognised Purview sensitivity label or caller clearance level; failing closed.'
    }
}

# 3. Sensitivity Label Exceeds Caller Clearance or Overshared Highly Confidential Site
if ($chunkRank -gt $callerRank -or ($GroundingCase.purviewLabel -eq 'Highly Confidential' -and $GroundingCase.hasEveryoneExceptExternalLink)) {
    return [PSCustomObject]@{
        CaseId                 = $GroundingCase.caseId
        ChunkId                = $GroundingCase.chunkId
        SiteUrl                = $GroundingCase.siteUrl
        PurviewLabel           = $GroundingCase.purviewLabel
        Decision               = 'BLOCK_OVERSHARED_HIGHLY_CONFIDENTIAL'
        PermittedForGrounding  = $false
        RequiresSiteQuarantine = [bool]$GroundingCase.hasEveryoneExceptExternalLink
        Reason                 = "Purview label '$($GroundingCase.purviewLabel)' exceeds caller clearance '$($GroundingCase.callerClearanceLevel)' or is exposed via EEEU link."
    }
}

return [PSCustomObject]@{
    CaseId                 = $GroundingCase.caseId
    ChunkId                = $GroundingCase.chunkId
    SiteUrl                = $GroundingCase.siteUrl
    PurviewLabel           = $GroundingCase.purviewLabel
    Decision               = 'PERMIT_GROUNDING_CHUNK'
    PermittedForGrounding  = $true
    RequiresSiteQuarantine = $false
    Reason                 = "Caller clearance '$($GroundingCase.callerClearanceLevel)' satisfies Purview label '$($GroundingCase.purviewLabel)'."
}
