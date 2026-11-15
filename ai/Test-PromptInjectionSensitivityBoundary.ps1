# Test-PromptInjectionSensitivityBoundary.ps1
<#
.SYNOPSIS
    Detects indirect prompt-injection payloads inside retrieved Azure AI Search / SharePoint RAG chunks
    attempting to bypass Microsoft Purview sensitivity label enforcement.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ChunkText,

    [Parameter()]
    [string]$ChunkId = 'unknown'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$injectionPatterns = @(
    '(?i)ignore\s+(all\s+)?(purview|sensitivity)\s+labels',
    '(?i)print\s+all\s+highly\s+confidential',
    '(?i)bypass\s+(dspm|dlp|rbac|acl)',
    '(?i)ignore\s+previous\s+system\s+instructions',
    '(?i)exfiltrate\s+to\s+external'
)

$hits = foreach ($p in $injectionPatterns) {
    if ($ChunkText -match $p) { $p }
}

return [PSCustomObject]@{
    ChunkId          = $ChunkId
    InjectionDetected = (@($hits).Count -gt 0)
    MatchedRules     = @($hits)
    Verdict          = if (@($hits).Count -gt 0) { 'QUARANTINE_INDIRECT_PROMPT_INJECTION' } else { 'CLEAN_GROUNDING_TEXT' }
}
