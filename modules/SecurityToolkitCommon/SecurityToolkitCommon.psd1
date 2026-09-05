@{
    RootModule        = 'SecurityToolkitCommon.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b6e2f1a4-4b2a-4b1e-9c3a-2f6a8e1d7c90'
    Author            = 'Security Engineering'
    Description       = 'Shared logging, CSV/JSON/HTML/Excel/PDF export, and connection-check helpers used across the security audit toolkit scripts.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Write-SecurityLog',
        'Export-SecurityReport',
        'New-SecurityFinding',
        'Assert-ModuleAvailable',
        'Test-AzContext',
        'Test-GraphContext',
        'Test-OptionalModule',
        'New-SecurityReportHtml',
        'Export-SecurityReportExcel',
        'Export-SecurityReportPdf',
        'Convert-HtmlToPdfViaBrowser'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
