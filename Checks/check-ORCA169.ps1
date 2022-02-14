<#

169

Determines if ATP SafeLinks protection extends to Office Apps in each policy,
Does not however determine if SafeLinks policy extends to all users.

#>

using module "..\ORCA.psm1"

class ORCA169 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA169()
    {
        $this.Control=169
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Safe Links Office Enablement"
        $this.PassText="Safe Links is enabled for Office ProPlus, Office for iOS and Android"
        $this.FailRecommendation="Enable Safe Links for Office ProPlus, Office for iOS and Android"
        $this.Importance="Phishing attacks are not limited to email messages. Malicious URLs can be delivered using Office documents as well. Configuring Office 365 ATP Safe Links for Office ProPlus,  Office for iOS and Android can help combat against these attacks via providing time-of-click verification of web addresses (URLs) in Office documents."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ChiValue=[ORCACHI]::High
        $this.ObjectType="Safe Links Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.Links= @{
            "Security & Compliance Center - Safe links"="https://aka.ms/orca-atpp-action-safelinksv2"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        $ConfigObject = [ORCACheckConfig]::new()
        $ConfigObject.Object=$Config["AtpPolicy"].Name
        $ConfigObject.ConfigItem="EnableSafeLinksForO365Clients"
        $ConfigObject.ConfigData=$Config["AtpPolicy"].EnableSafeLinksForO365Clients

        If($Config["AtpPolicy"].EnableSafeLinksForO365Clients -eq $false)
        {   
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
        }
        Else 
        {
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
        }   

        $this.AddConfig($ConfigObject)

    }

}