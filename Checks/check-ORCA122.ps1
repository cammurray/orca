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
        $this.ChiValue=[ORCACHI]::VeryHigh
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        If($Config["AdminAuditLogConfig"].UnifiedAuditLogIngestionEnabled -eq $false) 
        {

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem="UnifiedAuditLogIngestionEnabled"
            $ConfigObject.ConfigData=$Config["AdminAuditLogConfig"].UnifiedAuditLogIngestionEnabled
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
        
            $this.AddConfig($ConfigObject)
    
        }   

    }

}