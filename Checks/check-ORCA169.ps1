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
        $this.Name="Office Enablement"
        $this.PassText="Safe Links is enabled for Office ProPlus, Office for iOS and Android"
        $this.FailRecommendation="Enable Safe Links for Office ProPlus, Office for iOS and Android"
        $this.Importance="Phishing attacks are not limited to email messages. Malicious URLs can be delivered using Office documents as well. Configuring Office 365 ATP Safe Links for Office ProPlus,  Office for iOS and Android can help combat against these attacks via providing time-of-click verification of web addresses (URLs) in Office documents."
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        If($Config["AtpPolicy"].EnableSafeLinksForClients -eq $false)
        {

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem="EnableSafeLinksForClients"
            $ConfigObject.ConfigData=$Config["AtpPolicy"].EnableSafeLinksForClients
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

            $this.AddConfig($ConfigObject)

        }     

    }

}