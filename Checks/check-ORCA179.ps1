<#

179

Checks to determine if SafeLinks is re-wring internal to internal emails. Does not however,
check to determine if there is a rule enforcing this.

#>

using module "..\ORCA.psm1"

class ORCA179 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA179()
    {
        $this.Control=179
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Intra-organization Safe Links"
        $this.PassText="Safe Links is enabled intra-organization"
        $this.FailRecommendation="Enable Safe Links between internal users"
        $this.ExpandResults=$True
        $this.ChiValue=[ORCACHI]::High
        $this.Importance="Phishing attacks are not limited from external users. Commonly, when one user is compromised, that user can be used in a process of lateral movement between different accounts in your organization. Configuring Safe Links so that internal messages are also re-written can assist with lateral movement using phishing."
        $this.ItemName="SafeLinks Policy"
        $this.DataType="Enabled for Internal"
        $this.Links= @{
            "Security & Compliance Center - Safe links"="https://protection.office.com/safelinksconverged"
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#office-365-advanced-threat-protection-security"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        $Enabled = $False

        ForEach($Policy in $Config["SafeLinksPolicy"]) 
        {
            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$($Policy.Name)
            $ConfigObject.ConfigData=$Policy.EnableForInternalSenders

            # Determine if ATP link tracking is on for this safelinks policy
            If($Policy.EnableForInternalSenders -eq $true) 
            {
                $Enabled = $True
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            } 
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }

            $this.AddConfig($ConfigObject)
        }

        If($Enabled -eq $False)
        {

            # No policy enabling
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem="All"
            $ConfigObject.ConfigData="Enabled False"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

            $this.AddConfig($ConfigObject)

        }    

    }

}