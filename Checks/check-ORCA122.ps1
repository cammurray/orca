using module "..\ORCA.psm1"

class ORCA122 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA122()
    {
        $this.Control=122
        $this.Area="Tenant Settings"
        $this.Name="Unified Audit Log"
        $this.PassText="Unified Audit Log is enabled"
        $this.FailRecommendation="Enable the Unified Audit Log"
        $this.Importance="The Unified Audit Log collects logs from most Office 365 services and provides one central place to correlate and pull logs from Office 365."
    
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        If($Config["AdminAuditLogConfig"].UnifiedAuditLogIngestionEnabled -eq $true) {
    
            # Unified audit logging turned on
    
            $this.Results += New-Object -TypeName psobject -Property @{
                Result="Pass"
                ConfigItem="UnifiedAuditLogIngestionEnabled"
                ConfigData=$Config["AdminAuditLogConfig"].UnifiedAuditLogIngestionEnabled
                Rule="UnifiedAuditLogIngestionEnabled is true"
                Control=$this.Control
            } 
    
        } else {
    
            # Unified audit logging turned off
    
            $this.Results += New-Object -TypeName psobject -Property @{
                Result="Fail"
                ConfigItem="UnifiedAuditLogIngestionEnabled"
                ConfigData=$Config["AdminAuditLogConfig"].UnifiedAuditLogIngestionEnabled
                Rule="UnifiedAuditLogIngestionEnabled is false"
                Control=$this.Control
            } 
    
        }        

    }

}