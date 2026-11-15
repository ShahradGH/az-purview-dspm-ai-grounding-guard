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
    [PSCustomObject]$GroundingCase,

    [Parameter()]
    [string]$FoundryEndpoint = '',

    [Parameter()]
    [string]$FoundryApiKey = '',

    [Parameter()]
    [string]$FoundryDeployment = 'gpt-4o',

    [Parameter()]
    [string]$FoundryApiVersion = '2024-10-21',

    [Parameter()]
    [switch]$UseLiveFoundry
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($UseLiveFoundry) {
    if ([string]::IsNullOrWhiteSpace($FoundryEndpoint)) {
        throw [System.ArgumentException]::new('Fail-closed: -FoundryEndpoint is required when -UseLiveFoundry is specified.')
    }
    if ($FoundryEndpoint -notmatch '^https://') {
        throw [System.ArgumentException]::new('Fail-closed: -FoundryEndpoint must use https://.')
    }
}

function Get-FoundryAuthHeader {
    param([string]$ApiKey)
    if (-not [string]::IsNullOrWhiteSpace($ApiKey)) {
        return @{
            'api-key'      = $ApiKey
            'Content-Type' = 'application/json'
        }
    }
    if (Get-Command -Name 'Get-AzAccessToken' -ErrorAction SilentlyContinue) {
        $tok = Get-AzAccessToken -ResourceUrl 'https://cognitiveservices.azure.com' -ErrorAction Stop
        $rawToken = if ($tok.Token -is [System.Security.SecureString]) {
            [System.Net.NetworkCredential]::new('', $tok.Token).Password
        } else {
            [string]$tok.Token
        }
        return @{
            'Authorization' = "Bearer $rawToken"
            'Content-Type'  = 'application/json'
        }
    }
    $imdsUri = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://cognitiveservices.azure.com'
    $imdsResp = Invoke-RestMethod -Method Get -Uri $imdsUri -Headers @{ Metadata = 'true' } -TimeoutSec 5 -ErrorAction Stop
    return @{
        'Authorization' = "Bearer $($imdsResp.access_token)"
        'Content-Type'  = 'application/json'
    }
}

function Invoke-FoundryJsonInference {
    param(
        [string]$Endpoint,
        [string]$ApiKey,
        [string]$Deployment,
        [string]$ApiVersion,
        [string]$SystemPrompt,
        [hashtable]$Payload
    )
    $uri = if ($Endpoint -match '/chat/completions') {
        $Endpoint
    } else {
        "$($Endpoint.TrimEnd('/'))/openai/deployments/$Deployment/chat/completions?api-version=$ApiVersion"
    }
    $headers = Get-FoundryAuthHeader -ApiKey $ApiKey
    $body = @{
        temperature     = 0.0
        response_format = @{ type = 'json_object' }
        messages        = @(
            @{ role = 'system'; content = $SystemPrompt },
            @{ role = 'user'; content = ($Payload | ConvertTo-Json -Depth 6 -Compress) }
        )
    } | ConvertTo-Json -Depth 8 -Compress

    $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body -TimeoutSec 30 -ErrorAction Stop
    $content = $resp.choices[0].message.content
    return ($content | ConvertFrom-Json -ErrorAction Stop)
}

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

$decision = 'PERMIT_GROUNDING_CHUNK'
$permitted = $true
$requiresQuarantine = $false
$reason = "Caller clearance '$($GroundingCase.callerClearanceLevel)' satisfies Purview label '$($GroundingCase.purviewLabel)'."
$inferenceMode = 'DETERMINISTIC_LOCAL'
$foundryRationale = $null

if ($UseLiveFoundry) {
    $allowedDecisions = @('PERMIT_GROUNDING_CHUNK', 'QUARANTINE_INDIRECT_PROMPT_INJECTION', 'BLOCK_OVERSHARED_HIGHLY_CONFIDENTIAL', 'ABSTAIN_UNLABELED_OVERSHARED_SITE')
    try {
        $foundryResult = Invoke-FoundryJsonInference `
            -Endpoint $FoundryEndpoint `
            -ApiKey $FoundryApiKey `
            -Deployment $FoundryDeployment `
            -ApiVersion $FoundryApiVersion `
            -SystemPrompt 'You are a Microsoft Purview DSPM for AI grounding auditor. Return JSON with keys: decision (PERMIT_GROUNDING_CHUNK|QUARANTINE_INDIRECT_PROMPT_INJECTION|BLOCK_OVERSHARED_HIGHLY_CONFIDENTIAL|ABSTAIN_UNLABELED_OVERSHARED_SITE), rationale (string).' `
            -Payload @{
                caseId              = $GroundingCase.caseId
                chunkId             = $GroundingCase.chunkId
                purviewLabel        = $GroundingCase.purviewLabel
                callerClearance     = $GroundingCase.callerClearanceLevel
                hasEeeuLink         = [bool]$GroundingCase.hasEveryoneExceptExternalLink
                chunkTextPreview    = ($GroundingCase.chunkText.Substring(0, [Math]::Min(240, $GroundingCase.chunkText.Length)))
            }

        $llmDecision = if ($null -ne $foundryResult.PSObject.Properties['decision']) { [string]$foundryResult.decision } else { '' }
        if ($llmDecision -in $allowedDecisions) {
            $decision = $llmDecision
            $permitted = ($decision -eq 'PERMIT_GROUNDING_CHUNK')
            $requiresQuarantine = ($decision -ne 'PERMIT_GROUNDING_CHUNK')
            $inferenceMode = 'LIVE_FOUNDRY'
            if ($null -ne $foundryResult.PSObject.Properties['rationale']) {
                $foundryRationale = [string]$foundryResult.rationale
                $reason = $foundryRationale
            }
        } else {
            Write-Warning "Foundry returned invalid DSPM decision '$llmDecision'; falling back to deterministic Purview gate."
            $inferenceMode = 'DETERMINISTIC_FALLBACK'
        }
    } catch {
        Write-Warning "Live Foundry inference failed ($($_.Exception.Message)); falling back to deterministic Purview gate."
        $inferenceMode = 'DETERMINISTIC_FALLBACK'
    }
}

return [PSCustomObject]@{
    CaseId                 = $GroundingCase.caseId
    ChunkId                = $GroundingCase.chunkId
    SiteUrl                = $GroundingCase.siteUrl
    PurviewLabel           = $GroundingCase.purviewLabel
    Decision               = $decision
    PermittedForGrounding  = $permitted
    RequiresSiteQuarantine = $requiresQuarantine
    Reason                 = $reason
    InferenceMode          = $inferenceMode
    FoundryRationale       = $foundryRationale
}
