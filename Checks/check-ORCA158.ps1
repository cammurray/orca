<#

158 Checks to determine if ATP is enabled for SharePoint, Teams, and OD4B as per 'tickbox' in the ATP configuration.

#>

using module "..\ORCA.psm1"

class ORCA158 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA158()
    {
        $this.Control=158
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Safe Attachments SharePoint and Teams"
        $this.PassText="Safe Attachments is enabled for SharePoint and Teams"
        $this.FailRecommendation="Enable Safe Attachments for SharePoint and Teams"
        $this.Importance="Safe Attachments can assist by scanning for zero day malware by using behavioural analysis and sandboxing techniques. These checks suppliment signature definitions."
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        # Determine if ATP is enabled or not
        If($Config["AtpPolicy"].EnableATPForSPOTeamsODB -eq $false) 
        {
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem="EnableATPForSPOTeamsODB"
            $ConfigObject.ConfigData=$Config["AtpPolicy"].EnableATPForSPOTeamsODB
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            $this.AddConfig($ConfigObject)

        } 

    }

}