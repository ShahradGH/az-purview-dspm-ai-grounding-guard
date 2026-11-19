BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:AuditScript = Join-Path $script:RepoRoot 'ai/Invoke-GroundingLeakageAudit.ps1'
    $script:BoundaryScript = Join-Path $script:RepoRoot 'ai/Test-PromptInjectionSensitivityBoundary.ps1'
    $script:CasesPath = Join-Path $script:RepoRoot 'ai/dspm-grounding-eval-cases.json'
    $script:GraphQuarantineScript = Join-Path $script:RepoRoot 'graph/Invoke-SharePointOversharingQuarantine.ps1'
    $script:KqlPath = Join-Path $script:RepoRoot 'queries/Purview-AiGrounding-Exposure.kql'
    $script:Cases = Get-Content -Path $script:CasesPath -Raw | ConvertFrom-Json
}

Describe 'Microsoft Purview DSPM for AI & Grounding Leakage Guard Verification Suite' {
    Context 'AI Subcomponent: Grounding Sensitivity & Indirect Prompt-Injection Gates' {
        It 'Permits General chunk when caller holds Confidential clearance (DSPM-301)' {
            $case = $script:Cases | Where-Object { $_.caseId -eq 'DSPM-301' }
            $res = & $script:AuditScript -GroundingCase $case
            $res.Decision | Should -Be 'PERMIT_GROUNDING_CHUNK'
            $res.PermittedForGrounding | Should -BeTrue
            $res.RequiresSiteQuarantine | Should -BeFalse
        }

        It 'Blocks overshared Highly Confidential M&A chunk and flags quarantine (DSPM-302)' {
            $case = $script:Cases | Where-Object { $_.caseId -eq 'DSPM-302' }
            $res = & $script:AuditScript -GroundingCase $case
            $res.Decision | Should -Be 'BLOCK_OVERSHARED_HIGHLY_CONFIDENTIAL'
            $res.PermittedForGrounding | Should -BeFalse
            $res.RequiresSiteQuarantine | Should -BeTrue
        }

        It 'Quarantines indirect prompt-injection inside retrieved SharePoint text (DSPM-303)' {
            $case = $script:Cases | Where-Object { $_.caseId -eq 'DSPM-303' }
            $res = & $script:AuditScript -GroundingCase $case
            $res.Decision | Should -Be 'QUARANTINE_INDIRECT_PROMPT_INJECTION'
            $res.PermittedForGrounding | Should -BeFalse
        }

        It 'Abstains on unlabeled chunk from EEEU-overshared SharePoint site (DSPM-304)' {
            $case = $script:Cases | Where-Object { $_.caseId -eq 'DSPM-304' }
            $res = & $script:AuditScript -GroundingCase $case
            $res.Decision | Should -Be 'ABSTAIN_UNLABELED_OVERSHARED_SITE'
            $res.PermittedForGrounding | Should -BeFalse
            $res.RequiresSiteQuarantine | Should -BeTrue
        }

        It 'Test-PromptInjectionSensitivityBoundary returns CLEAN_GROUNDING_TEXT for benign text' {
            $res = & $script:BoundaryScript -ChunkText 'Contoso standard retention policy is 7 years.' -ChunkId 'chunk-clean'
            $res.InjectionDetected | Should -BeFalse
            $res.Verdict | Should -Be 'CLEAN_GROUNDING_TEXT'
        }

        It 'Fails closed when -UseLiveFoundry is set without -FoundryEndpoint and supports mocked live Foundry REST call' {
            $case = $script:Cases | Where-Object { $_.caseId -eq 'DSPM-301' }
            { & $script:AuditScript -GroundingCase $case -UseLiveFoundry } | Should -Throw '*FoundryEndpoint*'

            Mock Invoke-RestMethod {
                return [PSCustomObject]@{
                    choices = @(
                        [PSCustomObject]@{
                            message = [PSCustomObject]@{
                                content = '{"decision":"PERMIT_GROUNDING_CHUNK","rationale":"General chunk cleared for Confidential caller."}'
                            }
                        }
                    )
                }
            }

            $res = & $script:AuditScript -GroundingCase $case -UseLiveFoundry -FoundryEndpoint 'https://contoso-foundry.openai.azure.com' -FoundryApiKey 'test-key'
            $res.InferenceMode | Should -Be 'LIVE_FOUNDRY'
            $res.Decision | Should -Be 'PERMIT_GROUNDING_CHUNK'
            Should -Invoke Invoke-RestMethod -Times 1
        }
    }

    Context 'Microsoft Graph v2.x SharePoint Quarantine & Zero-Leak Governance' {
        It 'Builds valid Graph v1.0 permissions URI and CISO Teams Adaptive Card in DryRun mode' {
            $case = $script:Cases | Where-Object { $_.caseId -eq 'DSPM-302' }
            $verdict = & $script:AuditScript -GroundingCase $case
            $res = & $script:GraphQuarantineScript -AuditVerdict $verdict -SiteId 'contoso.sharepoint.com,1111,2222' -TeamId '00000000-0000-0000-0000-000000000001' -ChannelId '19:ciso@thread.tacv2' -DryRun
            $res.Status | Should -Be 'DRY_RUN_PREPARED'
            $res.PermissionsUri | Should -Be 'https://graph.microsoft.com/v1.0/sites/contoso.sharepoint.com,1111,2222/permissions'
            $res.TeamsPayload.attachments[0].contentType | Should -Be 'application/vnd.microsoft.card.adaptive'
        }

        It 'Contains zero Bicep or Terraform files and zero internal sequence tags' {
            $iac = Get-ChildItem -Path $script:RepoRoot -Recurse -File | Where-Object { $_.Extension -in '.bicep', '.tf' }
            $iac.Count | Should -Be 0
            (Get-Content (Join-Path $script:RepoRoot 'README.md') -Raw) | Should -Not -Match 'Decision Pack 0|mvpfoundry\.alerasoul\.net|idea-020'
            (Get-Content $script:KqlPath -Raw) | Should -Match 'CloudAppEvents'
            (Get-Item (Join-Path $script:RepoRoot 'docs/DSPM-AI-GOVERNANCE-RUNBOOK.md')).Length | Should -BeGreaterThan 2048
        }
    }

    Context 'Identity & Microsoft Graph v2.x Purview Clearance Module' {
        BeforeAll {
            Import-Module (Join-Path $script:RepoRoot 'identity/PurviewIdentityClearance.psd1') -Force
        }

        It 'Maps Entra ID transitive security group to Highly Confidential clearance rank' {
            $mockGraph = {
                param($m, $u, $b)
                return [PSCustomObject]@{
                    value = @(
                        [PSCustomObject]@{ id = 'g-1'; displayName = 'SG-Clearance-HighlyConfidential' }
                    )
                }
            }

            $res = Get-EntraCallerClearanceTier -UserPrincipalName 'ciso@contoso.com' -GraphInvoker $mockGraph
            $res.MaxLabelTier | Should -Be 'Highly Confidential'
            $res.ClearanceRank | Should -Be 3
        }

        It 'Flags SharePoint sites with EEEU or spo-grid-all-users grants as unsafe for AI grounding' {
            $mockGraph = {
                param($m, $u, $b)
                return [PSCustomObject]@{
                    value = @(
                        [PSCustomObject]@{
                            id = 'perm-eeeu'
                            roles = @('read')
                            grantedToIdentitiesV2 = @([PSCustomObject]@{ siteUser = @{ loginName = 'spo-grid-all-users/tenant' } })
                        }
                    )
                }
            }

            $res = Test-SharePointSiteGuestExposure -SiteId 'contoso.sharepoint.com,1,2' -GraphInvoker $mockGraph
            $res.SafeForAiGrounding | Should -BeFalse
            $res.OversharedGrantCount | Should -Be 1
        }

        It 'Revokes overshared SharePoint permission grant via Graph DELETE' {
            $mockGraph = { param($m, $u, $b) return $null }
            $res = Revoke-SharePointOversharingGrant -SiteId 'contoso.sharepoint.com,1,2' -PermissionId 'perm-eeeu' -GraphInvoker $mockGraph
            $res.Revoked | Should -BeTrue
        }
    }
}
