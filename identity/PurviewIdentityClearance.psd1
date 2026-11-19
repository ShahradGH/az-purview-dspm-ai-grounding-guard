@{
    RootModule        = 'PurviewIdentityClearance.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '11111111-2222-3333-4444-555555550004'
    Author            = 'ShahradGH'
    CompanyName       = 'Independent Architecture'
    Copyright         = '(c) ShahradGH. MIT License.'
    Description       = 'Microsoft Graph v2.x Entra ID clearance tier resolution and SharePoint oversharing audit/revocation for Purview DSPM AI Grounding Guard.'
    PowerShellVersion = '7.4'
    FunctionsToExport = @(
        'Get-EntraCallerClearanceTier',
        'Test-SharePointSiteGuestExposure',
        'Revoke-SharePointOversharingGrant'
    )
}
